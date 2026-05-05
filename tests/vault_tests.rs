//! Integration tests for the Vault Transit key provider.
//!
//! Uses an in-process axum server to mock the Vault Transit engine endpoints.

#![cfg(feature = "vault")]

use std::net::SocketAddr;
use std::sync::Arc;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::crypto::{self, KeyProvider, LocalKeyProvider, VaultTransitProvider};
use peat_gateway::tenant::models::EnrollmentPolicy;
use peat_gateway::tenant::TenantManager;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

// ── Mock Vault Transit Server ──────────────────────────────────────────────

#[derive(Clone)]
struct VaultState {
    internal_key: [u8; 32],
    expected_token: String,
    /// Override response: if set, return this status + body instead of normal logic.
    override_response: Arc<Mutex<Option<(StatusCode, String)>>>,
    /// If true, return malformed JSON.
    malformed_json: Arc<Mutex<bool>>,
    /// If true, return invalid base64 in plaintext field.
    invalid_base64: Arc<Mutex<bool>>,
}

impl VaultState {
    fn new(key: [u8; 32], token: &str) -> Self {
        Self {
            internal_key: key,
            expected_token: token.to_string(),
            override_response: Arc::new(Mutex::new(None)),
            malformed_json: Arc::new(Mutex::new(false)),
            invalid_base64: Arc::new(Mutex::new(false)),
        }
    }
}

#[derive(Deserialize)]
struct EncryptReq {
    plaintext: String,
}

#[derive(Serialize)]
struct EncryptResp {
    data: EncryptRespData,
}

#[derive(Serialize)]
struct EncryptRespData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptReq {
    ciphertext: String,
}

#[derive(Serialize)]
struct DecryptResp {
    data: DecryptRespData,
}

#[derive(Serialize)]
struct DecryptRespData {
    plaintext: String,
}

fn b64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

async fn vault_encrypt_handler(
    State(state): State<VaultState>,
    Path(_key): Path<String>,
    headers: HeaderMap,
    Json(body): Json<EncryptReq>,
) -> (StatusCode, String) {
    // Check override
    if let Some((status, body)) = state.override_response.lock().await.clone() {
        return (status, body);
    }

    // Check token
    let token = headers
        .get("X-Vault-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if token != state.expected_token {
        return (
            StatusCode::FORBIDDEN,
            r#"{"errors":["permission denied"]}"#.into(),
        );
    }

    // Decrypt the base64 plaintext
    let plaintext = b64_decode(&body.plaintext);

    // Encrypt with internal key
    let cipher = Aes256Gcm::new_from_slice(&state.internal_key).unwrap();
    let mut nonce_bytes = [0u8; 12];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext.as_ref())
        .unwrap();

    // Build Vault-style ciphertext: "vault:v1:<base64(nonce+ct)>"
    let mut combined = Vec::with_capacity(12 + ct.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ct);
    let vault_ct = format!("vault:v1:{}", b64_encode(&combined));

    let resp = EncryptResp {
        data: EncryptRespData {
            ciphertext: vault_ct,
        },
    };

    (StatusCode::OK, serde_json::to_string(&resp).unwrap())
}

async fn vault_decrypt_handler(
    State(state): State<VaultState>,
    Path(_key): Path<String>,
    headers: HeaderMap,
    Json(body): Json<DecryptReq>,
) -> (StatusCode, String) {
    // Check override
    if let Some((status, body)) = state.override_response.lock().await.clone() {
        return (status, body);
    }

    // Check malformed JSON flag
    if *state.malformed_json.lock().await {
        return (StatusCode::OK, "not valid json at all {{{{".into());
    }

    // Check token
    let token = headers
        .get("X-Vault-Token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if token != state.expected_token {
        return (
            StatusCode::FORBIDDEN,
            r#"{"errors":["permission denied"]}"#.into(),
        );
    }

    // Check invalid base64 flag
    if *state.invalid_base64.lock().await {
        let resp = DecryptResp {
            data: DecryptRespData {
                plaintext: "!!!not-base64!!!".into(),
            },
        };
        return (StatusCode::OK, serde_json::to_string(&resp).unwrap());
    }

    // Parse "vault:v1:<base64>" ciphertext
    let parts: Vec<&str> = body.ciphertext.splitn(3, ':').collect();
    if parts.len() != 3 || parts[0] != "vault" {
        return (
            StatusCode::BAD_REQUEST,
            r#"{"errors":["invalid ciphertext"]}"#.into(),
        );
    }

    let combined = b64_decode(parts[2]);
    if combined.len() < 12 + 16 {
        return (
            StatusCode::BAD_REQUEST,
            r#"{"errors":["ciphertext too short"]}"#.into(),
        );
    }

    let cipher = Aes256Gcm::new_from_slice(&state.internal_key).unwrap();
    let plaintext = match cipher.decrypt(Nonce::from_slice(&combined[..12]), &combined[12..]) {
        Ok(pt) => pt,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                r#"{"errors":["decryption failed"]}"#.into(),
            )
        }
    };

    let resp = DecryptResp {
        data: DecryptRespData {
            plaintext: b64_encode(&plaintext),
        },
    };

    (StatusCode::OK, serde_json::to_string(&resp).unwrap())
}

async fn start_mock_vault(state: VaultState) -> (String, VaultState) {
    let app = Router::new()
        .route("/v1/transit/encrypt/:key", post(vault_encrypt_handler))
        .route("/v1/transit/decrypt/:key", post(vault_decrypt_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), state)
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
async fn vault_seal_open_roundtrip() {
    let state = VaultState::new([0xAA; 32], "test-token");
    let (addr, _state) = start_mock_vault(state).await;

    let provider = VaultTransitProvider::new(&addr, "test-token", "my-key").unwrap();
    let plaintext = b"mesh genesis secret key material";

    let envelope = crypto::seal(&provider, plaintext).await.unwrap();
    assert_eq!(&envelope[..4], b"PENV");

    let recovered = crypto::open(&provider, &envelope).await.unwrap().unwrap();
    assert_eq!(recovered, plaintext);
}

#[tokio::test]
async fn vault_formation_lifecycle() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let config = base_config(&db_path);

    let state = VaultState::new([0xBB; 32], "lifecycle-token");
    let (addr, _state) = start_mock_vault(state).await;

    let provider: Arc<dyn KeyProvider> =
        Arc::new(VaultTransitProvider::new(&addr, "lifecycle-token", "peat-key").unwrap());

    let mgr = TenantManager::with_key_provider(&config, provider.clone(), true)
        .await
        .unwrap();

    mgr.create_org("vault-org".into(), "Vault Org".into())
        .await
        .unwrap();
    let formation = mgr
        .create_formation("vault-org", "vault-mesh".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    let genesis = mgr.load_genesis("vault-org", "vault-mesh").await.unwrap();
    assert_eq!(genesis.mesh_id(), formation.mesh_id);
    assert!(!genesis.mesh_id().is_empty());
}

#[tokio::test]
async fn vault_migrate_keys() {
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

    // Migrate using Vault provider
    let state = VaultState::new([0xCC; 32], "mig-token");
    let (addr, _state) = start_mock_vault(state).await;
    let provider: Arc<dyn KeyProvider> =
        Arc::new(VaultTransitProvider::new(&addr, "mig-token", "peat-key").unwrap());

    {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        let raw = store
            .get_genesis("mig-org", "mig-mesh")
            .await
            .unwrap()
            .unwrap();
        if !crypto::is_envelope(&raw) {
            let sealed = crypto::seal(provider.as_ref(), &raw).await.unwrap();
            store
                .store_genesis("mig-org", "mig-mesh", &sealed)
                .await
                .unwrap();
        }

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
async fn vault_403_forbidden() {
    let state = VaultState::new([0xDD; 32], "correct-token");
    let (addr, _state) = start_mock_vault(state).await;

    // Use wrong token
    let provider = VaultTransitProvider::new(&addr, "wrong-token", "my-key").unwrap();
    let result = provider.wrap_dek(&[0x42u8; 32]).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("403") || err.contains("Forbidden"),
        "Error should mention 403: {err}"
    );
}

#[tokio::test]
async fn vault_500_server_error() {
    let state = VaultState::new([0xEE; 32], "test-token");
    let (addr, state) = start_mock_vault(state).await;

    // Set override to return 500
    *state.override_response.lock().await = Some((
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"errors":["internal error"]}"#.into(),
    ));

    let provider = VaultTransitProvider::new(&addr, "test-token", "my-key").unwrap();
    let result = provider.wrap_dek(&[0x42u8; 32]).await;

    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("500"));
}

#[tokio::test]
async fn vault_unreachable_server() {
    // Use a port that's definitely not listening
    let provider = VaultTransitProvider::new("http://127.0.0.1:1", "token", "key").unwrap();
    let result = provider.wrap_dek(&[0x42u8; 32]).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn vault_malformed_json_response() {
    let state = VaultState::new([0xFF; 32], "test-token");
    let (addr, state) = start_mock_vault(state).await;

    // First encrypt normally so we have valid ciphertext
    let provider = VaultTransitProvider::new(&addr, "test-token", "my-key").unwrap();
    let wrapped = provider.wrap_dek(&[0x42u8; 32]).await.unwrap();

    // Then set malformed JSON flag for decrypt
    *state.malformed_json.lock().await = true;

    let result = provider.unwrap_dek(&wrapped).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn vault_invalid_base64_response() {
    let state = VaultState::new([0x11; 32], "test-token");
    let (addr, state) = start_mock_vault(state).await;

    // Encrypt normally
    let provider = VaultTransitProvider::new(&addr, "test-token", "my-key").unwrap();
    let wrapped = provider.wrap_dek(&[0x42u8; 32]).await.unwrap();

    // Set invalid base64 flag
    *state.invalid_base64.lock().await = true;

    let result = provider.unwrap_dek(&wrapped).await;
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("base64") || err.contains("Invalid"),
        "Error should mention base64: {err}"
    );
}

#[tokio::test]
async fn vault_cross_provider_failure() {
    let state = VaultState::new([0x22; 32], "test-token");
    let (addr, _state) = start_mock_vault(state).await;

    let vault_provider = VaultTransitProvider::new(&addr, "test-token", "my-key").unwrap();
    let local_provider = LocalKeyProvider::new([0x33; 32]);

    let plaintext = b"cross-provider test data";
    let envelope = crypto::seal(&vault_provider, plaintext).await.unwrap();

    // Local provider cannot open Vault-wrapped envelope
    assert!(crypto::open(&local_provider, &envelope).await.is_err());
}

#[tokio::test]
async fn local_to_vault_cross_provider_failure() {
    let state = VaultState::new([0x55; 32], "test-token");
    let (addr, _state) = start_mock_vault(state).await;

    let local_provider = LocalKeyProvider::new([0x66; 32]);
    let vault_provider = VaultTransitProvider::new(&addr, "test-token", "my-key").unwrap();

    let plaintext = b"cross-provider reverse test";
    let envelope = crypto::seal(&local_provider, plaintext).await.unwrap();

    // Vault provider cannot open locally-wrapped envelope
    assert!(crypto::open(&vault_provider, &envelope).await.is_err());
}

#[tokio::test]
async fn vault_wrong_token() {
    let state = VaultState::new([0x44; 32], "real-token");
    let (addr, _state) = start_mock_vault(state).await;

    let provider = VaultTransitProvider::new(&addr, "fake-token", "my-key").unwrap();
    let result = provider.wrap_dek(&[0x42u8; 32]).await;

    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("403"),
        "Should get 403 with wrong token: {err}"
    );
}
