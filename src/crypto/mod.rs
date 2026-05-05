//! Envelope encryption for key material at rest.
//!
//! The [`KeyProvider`] trait is the abstraction boundary — implement it to plug in
//! a different key management backend (KMS, Vault, HSM, or a proprietary crate).
//! The [`seal`] and [`open`] functions handle the envelope format and are agnostic
//! to where the KEK lives.

#[cfg(feature = "aws-kms")]
pub mod kms;
mod local;
#[cfg(feature = "vault")]
mod vault;

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use rand_core::RngCore;

#[cfg(feature = "aws-kms")]
pub use kms::AwsKmsProvider;
pub use local::LocalKeyProvider;
#[cfg(feature = "vault")]
pub use vault::VaultTransitProvider;

use crate::config::GatewayConfig;

// ── Trait ────────────────────────────────────────────────────────────────────

/// Wraps and unwraps data encryption keys (DEKs).
///
/// Implementations control where the key-encryption key (KEK) lives and how
/// DEK wrapping is performed. The wrapped DEK blob is opaque — providers manage
/// their own nonces, IV, and metadata internally.
///
/// The only contract is that `unwrap_dek(wrap_dek(dek))` returns the original DEK.
#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn wrap_dek(&self, dek: &[u8]) -> Result<Vec<u8>>;
    async fn unwrap_dek(&self, wrapped: &[u8]) -> Result<Vec<u8>>;
}

/// A no-op provider that stores genesis bytes in plaintext.
/// Used when `PEAT_KEK` is not configured (dev/test mode).
pub struct PlaintextProvider;

#[async_trait]
impl KeyProvider for PlaintextProvider {
    async fn wrap_dek(&self, _dek: &[u8]) -> Result<Vec<u8>> {
        bail!("PlaintextProvider does not wrap DEKs — configure a key provider")
    }
    async fn unwrap_dek(&self, _wrapped: &[u8]) -> Result<Vec<u8>> {
        bail!("PlaintextProvider does not unwrap DEKs — configure a key provider")
    }
}

// ── Envelope format ─────────────────────────────────────────────────────────
//
//  [ 4 bytes: magic "PENV" ]
//  [ 1 byte:  version (0x01) ]
//  [ 2 bytes: wrapped DEK length (LE u16) ]
//  [ N bytes: wrapped DEK (opaque, provider-specific) ]
//  [12 bytes: data nonce ]
//  [ M bytes: encrypted data (plaintext_len + 16-byte GCM tag) ]
//

const MAGIC: &[u8; 4] = b"PENV";
const VERSION: u8 = 0x01;
const FIXED_HEADER: usize = 4 + 1 + 2; // magic + version + wrapped_dek_len

/// Fill a buffer with cryptographically-secure random bytes.
fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    rand_core::OsRng.fill_bytes(&mut buf);
    buf
}

/// Encrypt `plaintext` using a fresh DEK, wrapping the DEK with `provider`.
pub async fn seal(provider: &dyn KeyProvider, plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // Generate random DEK and nonce
    let mut dek = random_bytes::<32>();
    let data_nonce = random_bytes::<12>();

    // Wrap DEK with provider (opaque blob — provider manages its own nonces)
    let wrapped_dek = provider.wrap_dek(&dek).await?;
    let wrapped_len = u16::try_from(wrapped_dek.len())
        .context("Wrapped DEK exceeds 65535 bytes — provider returned unreasonable output")?;

    // Encrypt plaintext with DEK
    let cipher = Aes256Gcm::new_from_slice(&dek).context("Failed to create AES-256-GCM cipher")?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&data_nonce), plaintext)
        .map_err(|e| anyhow::anyhow!("AES-GCM encryption failed: {e}"))?;

    // Zeroize DEK
    zeroize::Zeroize::zeroize(&mut dek);

    // Assemble envelope
    let mut envelope = Vec::with_capacity(FIXED_HEADER + wrapped_dek.len() + 12 + ciphertext.len());
    envelope.extend_from_slice(MAGIC);
    envelope.push(VERSION);
    envelope.extend_from_slice(&wrapped_len.to_le_bytes());
    envelope.extend_from_slice(&wrapped_dek);
    envelope.extend_from_slice(&data_nonce);
    envelope.extend_from_slice(&ciphertext);

    Ok(envelope)
}

/// Returns `true` if `data` starts with the envelope magic header.
pub fn is_envelope(data: &[u8]) -> bool {
    data.len() >= FIXED_HEADER && &data[..4] == MAGIC
}

/// Build a key provider from configuration.
///
/// Priority: KMS (if `aws-kms` feature + `kms_key_arn` set) → Vault (if `vault`
/// feature + `vault_addr` set) → Local (if `kek` set) → Plaintext.
///
/// Returns `(provider, encrypt_enabled)`.
pub async fn build_key_provider(config: &GatewayConfig) -> Result<(Arc<dyn KeyProvider>, bool)> {
    // AWS KMS
    if let Some(ref arn) = config.kms_key_arn {
        #[cfg(feature = "aws-kms")]
        {
            let provider = AwsKmsProvider::from_env(arn.clone()).await?;
            tracing::info!("Genesis envelope encryption enabled (AWS KMS)");
            return Ok((Arc::new(provider), true));
        }
        #[cfg(not(feature = "aws-kms"))]
        {
            let _ = arn;
            bail!("PEAT_KMS_KEY_ARN is set but the `aws-kms` feature is not compiled in");
        }
    }

    // Vault Transit
    if let Some(ref addr) = config.vault_addr {
        #[cfg(feature = "vault")]
        {
            let token = config.vault_token.as_ref().ok_or_else(|| {
                anyhow::anyhow!("PEAT_VAULT_ADDR is set but PEAT_VAULT_TOKEN is missing")
            })?;
            let key_name = config
                .vault_transit_key
                .as_deref()
                .unwrap_or("peat-gateway");
            let provider = VaultTransitProvider::new(addr, token, key_name)?;
            tracing::info!("Genesis envelope encryption enabled (Vault Transit)");
            return Ok((Arc::new(provider), true));
        }
        #[cfg(not(feature = "vault"))]
        {
            let _ = addr;
            bail!("PEAT_VAULT_ADDR is set but the `vault` feature is not compiled in");
        }
    }

    // Local KEK
    if let Some(ref kek_hex) = config.kek {
        let provider = LocalKeyProvider::from_hex(kek_hex)?;
        tracing::info!("Genesis envelope encryption enabled (local KEK)");
        return Ok((Arc::new(provider), true));
    }

    // Plaintext fallback
    tracing::info!("Genesis envelope encryption disabled (no key provider configured)");
    Ok((Arc::new(PlaintextProvider), false))
}

/// Decrypt an envelope produced by [`seal`]. Returns the original plaintext.
///
/// If `data` does not start with the envelope magic bytes, returns `None`
/// (indicating plaintext/legacy data that the caller should handle directly).
pub async fn open(provider: &dyn KeyProvider, data: &[u8]) -> Result<Option<Vec<u8>>> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

    // Check for envelope magic
    if data.len() < FIXED_HEADER || &data[..4] != MAGIC {
        return Ok(None); // Not an envelope — legacy plaintext
    }

    if data[4] != VERSION {
        bail!("Unsupported envelope version: {}", data[4]);
    }

    let wrapped_len = u16::from_le_bytes([data[5], data[6]]) as usize;
    let wrapped_end = FIXED_HEADER + wrapped_len;
    let nonce_end = wrapped_end + 12;

    if data.len() < nonce_end + 16 {
        bail!("Envelope too short: truncated ciphertext");
    }

    let wrapped_dek = &data[FIXED_HEADER..wrapped_end];
    let data_nonce = &data[wrapped_end..nonce_end];
    let ciphertext = &data[nonce_end..];

    // Unwrap DEK via provider
    let mut dek = provider.unwrap_dek(wrapped_dek).await?;
    if dek.len() != 32 {
        bail!(
            "KeyProvider.unwrap_dek must return 32 bytes, got {}",
            dek.len()
        );
    }

    // Decrypt
    let cipher = Aes256Gcm::new_from_slice(&dek).context("Failed to create AES-256-GCM cipher")?;
    let plaintext = cipher
        .decrypt(Nonce::from_slice(data_nonce), ciphertext)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed (wrong KEK?): {e}"))?;

    zeroize::Zeroize::zeroize(&mut dek);

    Ok(Some(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_seal_open() {
        let provider = LocalKeyProvider::new([0xABu8; 32]);
        let plaintext = b"mesh genesis secret key material here";

        let envelope = seal(&provider, plaintext).await.unwrap();
        assert_eq!(&envelope[..4], MAGIC);
        assert_eq!(envelope[4], VERSION);

        let recovered = open(&provider, &envelope).await.unwrap().unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[tokio::test]
    async fn open_returns_none_for_plaintext() {
        let provider = LocalKeyProvider::new([0xABu8; 32]);
        let result = open(&provider, b"not an envelope, just raw genesis bytes")
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn wrong_kek_fails_decryption() {
        let p1 = LocalKeyProvider::new([0xAAu8; 32]);
        let p2 = LocalKeyProvider::new([0xBBu8; 32]);

        let envelope = seal(&p1, b"secret").await.unwrap();
        assert!(open(&p2, &envelope).await.is_err());
    }

    #[tokio::test]
    async fn tampered_ciphertext_fails() {
        let provider = LocalKeyProvider::new([0xCCu8; 32]);
        let mut envelope = seal(&provider, b"secret").await.unwrap();
        let last = envelope.len() - 1;
        envelope[last] ^= 0xFF;
        assert!(open(&provider, &envelope).await.is_err());
    }

    #[tokio::test]
    async fn different_seals_produce_different_envelopes() {
        let provider = LocalKeyProvider::new([0xDDu8; 32]);
        let plaintext = b"same input";

        let e1 = seal(&provider, plaintext).await.unwrap();
        let e2 = seal(&provider, plaintext).await.unwrap();
        assert_ne!(e1, e2);

        assert_eq!(open(&provider, &e1).await.unwrap().unwrap(), plaintext);
        assert_eq!(open(&provider, &e2).await.unwrap().unwrap(), plaintext);
    }

    #[tokio::test]
    async fn empty_plaintext_roundtrip() {
        let provider = LocalKeyProvider::new([0xEEu8; 32]);
        let envelope = seal(&provider, b"").await.unwrap();
        let recovered = open(&provider, &envelope).await.unwrap().unwrap();
        assert!(recovered.is_empty());
    }

    // ── build_key_provider tests ──────────────────────────────────────────

    fn test_config() -> GatewayConfig {
        GatewayConfig {
            bind_addr: "127.0.0.1:0".into(),
            storage: crate::config::StorageConfig::Redb {
                path: "/dev/null".into(),
            },
            cdc: crate::config::CdcConfig {
                nats_url: None,
                kafka_brokers: None,
            },
            ui_dir: None,
            admin_token: None,
            kek: None,
            kms_key_arn: None,
            vault_addr: None,
            vault_token: None,
            vault_transit_key: None,
            mesh_brokers: vec![],
            mesh_poll_interval_ms: 5_000,
        }
    }

    #[tokio::test]
    async fn build_provider_plaintext_fallback() {
        let config = test_config();
        let (_, encrypt_enabled) = build_key_provider(&config).await.unwrap();
        assert!(!encrypt_enabled);
    }

    #[tokio::test]
    async fn build_provider_local_kek() {
        let mut config = test_config();
        config.kek = Some("aa".repeat(32));
        let (_, encrypt_enabled) = build_key_provider(&config).await.unwrap();
        assert!(encrypt_enabled);
    }

    #[cfg(not(feature = "aws-kms"))]
    #[tokio::test]
    async fn build_provider_kms_without_feature() {
        let mut config = test_config();
        config.kms_key_arn = Some("arn:aws:kms:us-east-1:000:key/test".into());
        let err = build_key_provider(&config)
            .await
            .err()
            .expect("should fail")
            .to_string();
        assert!(
            err.contains("aws-kms"),
            "Error should mention aws-kms feature: {err}"
        );
    }

    #[cfg(not(feature = "vault"))]
    #[tokio::test]
    async fn build_provider_vault_without_feature() {
        let mut config = test_config();
        config.vault_addr = Some("http://127.0.0.1:8200".into());
        let err = build_key_provider(&config)
            .await
            .err()
            .expect("should fail")
            .to_string();
        assert!(
            err.contains("vault"),
            "Error should mention vault feature: {err}"
        );
    }

    #[cfg(feature = "vault")]
    #[tokio::test]
    async fn build_provider_vault_addr_without_token() {
        let mut config = test_config();
        config.vault_addr = Some("http://127.0.0.1:8200".into());
        // vault_token is None
        let err = build_key_provider(&config)
            .await
            .err()
            .expect("should fail")
            .to_string();
        assert!(
            err.contains("PEAT_VAULT_TOKEN"),
            "Error should mention missing PEAT_VAULT_TOKEN: {err}"
        );
    }
}
