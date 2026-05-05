//! Integration tests for the AWS KMS key provider.
//!
//! Uses a `MockKmsOps` that does local AES wrapping to simulate KMS behavior
//! without requiring real AWS credentials.

#![cfg(feature = "aws-kms")]

use std::sync::Arc;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use async_trait::async_trait;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::crypto::{self, AwsKmsProvider, KeyProvider, LocalKeyProvider};
use peat_gateway::tenant::models::EnrollmentPolicy;
use peat_gateway::tenant::TenantManager;
use rand_core::RngCore;

// ── Mock KMS ───────────────────────────────────────────────────────────────

struct MockKmsOps {
    internal_key: [u8; 32],
}

impl MockKmsOps {
    fn new(key: [u8; 32]) -> Self {
        Self { internal_key: key }
    }
}

#[async_trait]
impl peat_gateway::crypto::kms::KmsOps for MockKmsOps {
    async fn encrypt(&self, _key_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new_from_slice(&self.internal_key).unwrap();
        let mut nonce_bytes = [0u8; 12];
        rand_core::OsRng.fill_bytes(&mut nonce_bytes);
        let ct = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
            .map_err(|e| anyhow::anyhow!("mock encrypt: {e}"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 + 16 {
            anyhow::bail!("MockKmsOps: ciphertext too short");
        }
        let cipher = Aes256Gcm::new_from_slice(&self.internal_key).unwrap();
        cipher
            .decrypt(Nonce::from_slice(&ciphertext[..12]), &ciphertext[12..])
            .map_err(|e| anyhow::anyhow!("mock decrypt: {e}"))
    }
}

fn mock_kms_provider(key: [u8; 32]) -> AwsKmsProvider {
    AwsKmsProvider::with_ops(Box::new(MockKmsOps::new(key)), "mock-key-arn".into())
}

fn base_config(db_path: &std::path::Path) -> GatewayConfig {
    GatewayConfig {
        bind_addr: "127.0.0.1:0".into(),
        storage: StorageConfig::Redb {
            path: db_path.to_str().unwrap().into(),
        },
        cdc: CdcConfig {
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

// ── Tests ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn kms_formation_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let config = base_config(&db_path);
    let provider: Arc<dyn KeyProvider> = Arc::new(mock_kms_provider([0xAA; 32]));

    let mgr = TenantManager::with_key_provider(&config, provider.clone(), true)
        .await
        .unwrap();

    mgr.create_org("kms-org".into(), "KMS Org".into())
        .await
        .unwrap();
    let formation = mgr
        .create_formation("kms-org", "kms-mesh".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    // Genesis loads and has a valid mesh_id
    let genesis = mgr.load_genesis("kms-org", "kms-mesh").await.unwrap();
    assert_eq!(genesis.mesh_id(), formation.mesh_id);
    assert!(!genesis.mesh_id().is_empty());
}

#[tokio::test]
async fn kms_genesis_is_encrypted_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let config = base_config(&db_path);
    let provider: Arc<dyn KeyProvider> = Arc::new(mock_kms_provider([0xBB; 32]));

    {
        let mgr = TenantManager::with_key_provider(&config, provider, true)
            .await
            .unwrap();
        mgr.create_org("enc-org".into(), "Enc Org".into())
            .await
            .unwrap();
        mgr.create_formation("enc-org", "enc-mesh".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
    }

    // Verify raw bytes have PENV header
    let store = peat_gateway::storage::open(&config.storage).await.unwrap();
    let raw = store
        .get_genesis("enc-org", "enc-mesh")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&raw[..4], b"PENV", "genesis should be envelope-encrypted");
}

#[tokio::test]
async fn kms_migrate_keys() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let config = base_config(&db_path);

    // Create plaintext formation
    {
        let mgr = TenantManager::new(&config).await.unwrap();
        mgr.create_org("mig-org".into(), "Mig Org".into())
            .await
            .unwrap();
        mgr.create_formation("mig-org", "mig-mesh".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
    }

    // Verify plaintext
    {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        let raw = store
            .get_genesis("mig-org", "mig-mesh")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(&raw[..4], b"PENV");
    }

    // Migrate using KMS provider
    let provider: Arc<dyn KeyProvider> = Arc::new(mock_kms_provider([0xCC; 32]));
    {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        let orgs = store.list_orgs().await.unwrap();
        for org in &orgs {
            let formations = store.list_formations(&org.org_id).await.unwrap();
            for formation in &formations {
                let raw = store
                    .get_genesis(&org.org_id, &formation.app_id)
                    .await
                    .unwrap()
                    .unwrap();
                if !crypto::is_envelope(&raw) {
                    let sealed = crypto::seal(provider.as_ref(), &raw).await.unwrap();
                    store
                        .store_genesis(&org.org_id, &formation.app_id, &sealed)
                        .await
                        .unwrap();
                }
            }
        }

        // Verify encrypted
        let raw = store
            .get_genesis("mig-org", "mig-mesh")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&raw[..4], b"PENV");
    }

    // Verify loadable
    let mgr = TenantManager::with_key_provider(&config, provider, true)
        .await
        .unwrap();
    let genesis = mgr.load_genesis("mig-org", "mig-mesh").await.unwrap();
    assert!(!genesis.mesh_id().is_empty());
}

#[tokio::test]
async fn kms_cross_provider_failure() {
    let kms_provider = mock_kms_provider([0xDD; 32]);
    let local_provider = LocalKeyProvider::new([0xEE; 32]);

    let plaintext = b"cross-provider test data";
    let envelope = crypto::seal(&kms_provider, plaintext).await.unwrap();

    // Local provider cannot open KMS-wrapped envelope
    assert!(crypto::open(&local_provider, &envelope).await.is_err());
}

#[tokio::test]
async fn local_to_kms_cross_provider_failure() {
    let local_provider = LocalKeyProvider::new([0xEE; 32]);
    let kms_provider = mock_kms_provider([0xDD; 32]);

    let plaintext = b"cross-provider reverse test";
    let envelope = crypto::seal(&local_provider, plaintext).await.unwrap();

    // KMS provider cannot open locally-wrapped envelope
    assert!(crypto::open(&kms_provider, &envelope).await.is_err());
}
