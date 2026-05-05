//! P0 hardening tests for single-node production readiness.
//!
//! Covers: corrupt genesis handling (#28), genesis without KEK (#29),
//! concurrent tenant operations (#30), and input validation (#31).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::models::EnrollmentPolicy;
use peat_gateway::tenant::TenantManager;
use serde_json::{json, Value};
use tower::ServiceExt;

// ── Helpers ──────────────────────────────────────────────────────

fn test_config(dir: &tempfile::TempDir, kek: Option<String>) -> GatewayConfig {
    let db_path = dir.path().join("test.redb");
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
        kek,
        kms_key_arn: None,
        vault_addr: None,
        vault_token: None,
        vault_transit_key: None,
        mesh_brokers: vec![],
        mesh_poll_interval_ms: 5_000,
    }
}

async fn setup() -> (TenantManager, axum::Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());
    (mgr, app, dir)
}

fn json_request(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    match body {
        Some(b) => builder.body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

async fn create_org(mgr: &TenantManager, org_id: &str) {
    mgr.create_org(org_id.into(), format!("{org_id} Corp"))
        .await
        .unwrap();
}

async fn create_open_formation(mgr: &TenantManager, org_id: &str, app_id: &str) {
    mgr.create_formation(org_id, app_id.into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
}

// ═══════════════════════════════════════════════════════════════════
// #28 — Corrupt/truncated genesis blob handling
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn corrupt_genesis_garbage_bytes_returns_error_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, Some("aa".repeat(32)));

    // Create org + formation, then drop to release redb lock
    {
        let mgr = TenantManager::new(&config).await.unwrap();
        create_org(&mgr, "corrupt-org").await;
        create_open_formation(&mgr, "corrupt-org", "good-formation").await;
    }

    // Overwrite genesis with garbage via raw storage
    {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        store
            .store_genesis("corrupt-org", "good-formation", b"totally garbage bytes")
            .await
            .unwrap();
    }

    // Reopen and attempt to load — should return an error, not panic
    let mgr = TenantManager::new(&config).await.unwrap();
    let result = mgr.load_genesis("corrupt-org", "good-formation").await;
    assert!(result.is_err(), "corrupt genesis should return Err");
    let err = result.unwrap_err().to_string();
    assert!(!err.is_empty(), "error message should be non-empty");
}

#[tokio::test]
async fn corrupt_genesis_truncated_envelope_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, Some("aa".repeat(32)));

    // Create, then read raw genesis, then drop lock
    let truncated = {
        let mgr = TenantManager::new(&config).await.unwrap();
        create_org(&mgr, "trunc-org").await;
        create_open_formation(&mgr, "trunc-org", "trunc-app").await;
        drop(mgr);

        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        let valid = store
            .get_genesis("trunc-org", "trunc-app")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&valid[..4], b"PENV", "should be encrypted");

        // Store only the first 10 bytes (truncated envelope)
        store
            .store_genesis("trunc-org", "trunc-app", &valid[..10])
            .await
            .unwrap();
        valid[..10].to_vec()
    };
    assert_eq!(truncated.len(), 10);

    let mgr = TenantManager::new(&config).await.unwrap();
    let result = mgr.load_genesis("trunc-org", "trunc-app").await;
    assert!(result.is_err(), "truncated envelope should return Err");
    let err = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err.contains("truncated") || err.contains("short") || err.contains("envelope"),
        "error should mention truncation: {err}"
    );
}

#[tokio::test]
async fn corrupt_genesis_invalid_version_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, Some("aa".repeat(32)));

    {
        let mgr = TenantManager::new(&config).await.unwrap();
        create_org(&mgr, "ver-org").await;
        create_open_formation(&mgr, "ver-org", "ver-app").await;
    }

    {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        let mut valid = store
            .get_genesis("ver-org", "ver-app")
            .await
            .unwrap()
            .unwrap();

        // Corrupt the version byte (index 4) to 0xFF
        valid[4] = 0xFF;
        store
            .store_genesis("ver-org", "ver-app", &valid)
            .await
            .unwrap();
    }

    let mgr = TenantManager::new(&config).await.unwrap();
    let result = mgr.load_genesis("ver-org", "ver-app").await;
    assert!(result.is_err(), "invalid version should return Err");
    let err = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err.contains("version"),
        "error should mention version: {err}"
    );
}

#[tokio::test]
async fn corrupt_genesis_enrollment_returns_graceful_degradation() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, Some("aa".repeat(32)));

    // Create org + formation, then drop to release lock for corruption
    {
        let mgr = TenantManager::new(&config).await.unwrap();
        create_org(&mgr, "enroll-corrupt").await;
        create_open_formation(&mgr, "enroll-corrupt", "broken-mesh").await;
    }

    // Corrupt genesis
    {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        store
            .store_genesis("enroll-corrupt", "broken-mesh", b"not valid genesis")
            .await
            .unwrap();
    }

    // Reopen with fresh manager for enrollment test
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr);

    // Enrollment with key material should still succeed (approved) but with no certificate
    // because try_issue_certificate gracefully degrades on genesis load failure
    let device = peat_mesh::security::DeviceKeypair::generate();
    let pk_hex = hex::encode(device.public_key_bytes());

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/enroll-corrupt/formations/broken-mesh/enroll",
            Some(json!({
                "public_key": pk_hex,
                "node_id": "test-node"
            })),
        ))
        .await
        .unwrap();

    // Open policy → approval succeeds, but cert issuance gracefully degrades
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["decision"]["Approved"]["tier"], "Endpoint");
    assert!(
        body["certificate"].is_null(),
        "corrupt genesis should yield no certificate"
    );
}

// ═══════════════════════════════════════════════════════════════════
// #29 — Genesis creation when KEK unavailable
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn formation_without_kek_stores_plaintext_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None); // No KEK

    {
        let mgr = TenantManager::new(&config).await.unwrap();
        create_org(&mgr, "plaintext-org").await;
        create_open_formation(&mgr, "plaintext-org", "plain-app").await;
    }

    // Raw storage should NOT have PENV header
    let store = peat_gateway::storage::open(&config.storage).await.unwrap();
    let raw = store
        .get_genesis("plaintext-org", "plain-app")
        .await
        .unwrap()
        .unwrap();
    assert_ne!(
        &raw[..4],
        b"PENV",
        "no-KEK genesis should be stored as plaintext"
    );

    // Should be valid MeshGenesis bytes
    assert!(
        peat_mesh::security::MeshGenesis::decode(&raw).is_ok(),
        "plaintext genesis should be decodeable"
    );
}

#[tokio::test]
async fn enrollment_against_plaintext_genesis_works() {
    let (mgr, app, _dir) = setup().await; // No KEK
    create_org(&mgr, "pt-org").await;
    create_open_formation(&mgr, "pt-org", "pt-mesh").await;

    let device = peat_mesh::security::DeviceKeypair::generate();
    let pk_hex = hex::encode(device.public_key_bytes());

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/pt-org/formations/pt-mesh/enroll",
            Some(json!({
                "public_key": pk_hex,
                "node_id": "plaintext-node"
            })),
        ))
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["decision"]["Approved"]["tier"], "Endpoint");
    let cert_hex = body["certificate"]
        .as_str()
        .expect("should issue cert from plaintext genesis");
    let cert =
        peat_mesh::security::MeshCertificate::decode(&hex::decode(cert_hex).unwrap()).unwrap();
    assert!(cert.verify().is_ok());
}

#[tokio::test]
async fn formation_with_kek_stores_encrypted_genesis() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, Some("cc".repeat(32)));

    {
        let mgr = TenantManager::new(&config).await.unwrap();
        create_org(&mgr, "enc-org").await;
        create_open_formation(&mgr, "enc-org", "enc-app").await;
    }

    let store = peat_gateway::storage::open(&config.storage).await.unwrap();
    let raw = store
        .get_genesis("enc-org", "enc-app")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &raw[..4],
        b"PENV",
        "KEK-enabled genesis should be envelope-encrypted"
    );
}

// ═══════════════════════════════════════════════════════════════════
// #30 — Concurrent tenant manager operations
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn concurrent_formation_creates_no_deadlock() {
    let (mgr, _app, _dir) = setup().await;
    create_org(&mgr, "conc-org").await;

    // Bump quota so we can create many formations
    mgr.update_org(
        "conc-org",
        None,
        Some(peat_gateway::tenant::models::OrgQuotas {
            max_formations: 100,
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    let mut handles = Vec::new();
    for i in 0..20 {
        let mgr = mgr.clone();
        handles.push(tokio::spawn(async move {
            mgr.create_formation("conc-org", format!("formation-{i}"), EnrollmentPolicy::Open)
                .await
        }));
    }

    let mut successes = 0;
    for h in handles {
        if h.await.unwrap().is_ok() {
            successes += 1;
        }
    }

    // All 20 should succeed (quota is 100)
    assert_eq!(successes, 20, "all concurrent creates should succeed");

    // Verify all formations exist
    let formations = mgr.list_formations("conc-org").await.unwrap();
    assert_eq!(formations.len(), 20);
}

#[tokio::test]
async fn concurrent_org_creates_no_deadlock() {
    let (mgr, _app, _dir) = setup().await;

    let mut handles = Vec::new();
    for i in 0..10 {
        let mgr = mgr.clone();
        handles.push(tokio::spawn(async move {
            mgr.create_org(format!("org-{i}"), format!("Org {i}")).await
        }));
    }

    let mut successes = 0;
    for h in handles {
        if h.await.unwrap().is_ok() {
            successes += 1;
        }
    }

    assert_eq!(successes, 10, "all concurrent org creates should succeed");
    let orgs = mgr.list_orgs().await.unwrap();
    assert_eq!(orgs.len(), 10);
}

#[tokio::test]
async fn concurrent_enrollment_and_formation_delete_no_panic() {
    let (mgr, _app, _dir) = setup().await;
    create_org(&mgr, "race-org").await;

    // Bump enrollment quota
    mgr.update_org(
        "race-org",
        None,
        Some(peat_gateway::tenant::models::OrgQuotas {
            max_formations: 100,
            max_enrollments_per_hour: 1_000_000,
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    create_open_formation(&mgr, "race-org", "race-mesh").await;
    let app = peat_gateway::api::app(mgr.clone());

    let mut handles = Vec::new();

    // Spawn enrollment requests
    for i in 0..10 {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            let device = peat_mesh::security::DeviceKeypair::generate();
            let pk_hex = hex::encode(device.public_key_bytes());
            let resp = app
                .oneshot(json_request(
                    "POST",
                    "/orgs/race-org/formations/race-mesh/enroll",
                    Some(json!({
                        "public_key": pk_hex,
                        "node_id": format!("node-{i}")
                    })),
                ))
                .await
                .unwrap();
            resp.status()
        }));
    }

    // Spawn a formation delete midway
    let mgr2 = mgr.clone();
    handles.push(tokio::spawn(async move {
        // Small yield to let some enrollments start
        tokio::task::yield_now().await;
        let _ = mgr2.delete_formation("race-org", "race-mesh").await;
        StatusCode::OK // placeholder
    }));

    // The key assertion: no panics, no deadlocks, all tasks complete
    for h in handles {
        let _ = h.await.unwrap();
    }
}

#[tokio::test]
async fn concurrent_sink_toggle_and_list_no_deadlock() {
    let (mgr, _app, _dir) = setup().await;
    create_org(&mgr, "sink-conc").await;

    // Bump sink quota
    mgr.update_org(
        "sink-conc",
        None,
        Some(peat_gateway::tenant::models::OrgQuotas {
            max_cdc_sinks: 100,
            ..Default::default()
        }),
    )
    .await
    .unwrap();

    // Create several sinks
    let mut sink_ids = Vec::new();
    for _ in 0..5 {
        let sink = mgr
            .create_sink(
                "sink-conc",
                peat_gateway::tenant::models::CdcSinkType::Nats {
                    subject_prefix: "test".into(),
                },
            )
            .await
            .unwrap();
        sink_ids.push(sink.sink_id);
    }

    let mut toggle_handles = Vec::new();
    let mut list_handles = Vec::new();

    // Toggle sinks concurrently
    for (i, sid) in sink_ids.iter().enumerate() {
        let mgr = mgr.clone();
        let sid = sid.clone();
        toggle_handles.push(tokio::spawn(async move {
            mgr.toggle_sink("sink-conc", &sid, i % 2 == 0).await
        }));
    }

    // List sinks concurrently
    for _ in 0..5 {
        let mgr = mgr.clone();
        list_handles.push(tokio::spawn(
            async move { mgr.list_sinks("sink-conc").await },
        ));
    }

    for h in toggle_handles {
        h.await.unwrap().unwrap();
    }
    for h in list_handles {
        h.await.unwrap().unwrap();
    }
}

// ═══════════════════════════════════════════════════════════════════
// #31 — Input validation
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn empty_org_id_rejected() {
    let (_mgr, app, _dir) = setup().await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs",
            Some(json!({"org_id": "", "display_name": "Empty Org"})),
        ))
        .await
        .unwrap();

    // Empty org_id should be rejected (400)
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty org_id should be rejected"
    );
}

#[tokio::test]
async fn empty_display_name_rejected() {
    let (_mgr, app, _dir) = setup().await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs",
            Some(json!({"org_id": "valid-org", "display_name": ""})),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty display_name should be rejected"
    );
}

#[tokio::test]
async fn empty_formation_app_id_rejected() {
    let (mgr, app, _dir) = setup().await;
    create_org(&mgr, "val-org").await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/val-org/formations",
            Some(json!({"app_id": ""})),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty app_id should be rejected"
    );
}

#[tokio::test]
async fn oversized_org_id_rejected() {
    let (_mgr, app, _dir) = setup().await;

    let huge_id = "a".repeat(10_000);
    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs",
            Some(json!({"org_id": huge_id, "display_name": "Huge"})),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "oversized org_id should be rejected"
    );
}

#[tokio::test]
async fn oversized_display_name_rejected() {
    let (_mgr, app, _dir) = setup().await;

    let huge_name = "X".repeat(10_000);
    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs",
            Some(json!({"org_id": "ok-org", "display_name": huge_name})),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "oversized display_name should be rejected"
    );
}

#[tokio::test]
async fn org_id_with_null_bytes_rejected() {
    let (_mgr, app, _dir) = setup().await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs",
            Some(json!({"org_id": "bad\0org", "display_name": "Null Byte Org"})),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "org_id with null bytes should be rejected"
    );
}

#[tokio::test]
async fn empty_token_label_rejected() {
    let (mgr, app, _dir) = setup().await;
    create_org(&mgr, "tok-org").await;
    create_open_formation(&mgr, "tok-org", "tok-mesh").await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/tok-org/tokens",
            Some(json!({
                "app_id": "tok-mesh",
                "label": ""
            })),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty token label should be rejected"
    );
}

#[tokio::test]
async fn webhook_url_file_scheme_rejected() {
    let (mgr, app, _dir) = setup().await;
    create_org(&mgr, "url-org").await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/url-org/sinks",
            Some(json!({
                "sink_type": {"Webhook": {"url": "file:///etc/passwd"}}
            })),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "file:// webhook URL should be rejected"
    );
}

#[tokio::test]
async fn webhook_url_empty_rejected() {
    let (mgr, app, _dir) = setup().await;
    create_org(&mgr, "url-org2").await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/url-org2/sinks",
            Some(json!({
                "sink_type": {"Webhook": {"url": ""}}
            })),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty webhook URL should be rejected"
    );
}

#[tokio::test]
async fn idp_issuer_url_empty_rejected() {
    let (mgr, app, _dir) = setup().await;
    create_org(&mgr, "idp-org").await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/idp-org/idps",
            Some(json!({
                "issuer_url": "",
                "client_id": "peat",
                "client_secret": "secret"
            })),
        ))
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty issuer_url should be rejected"
    );
}

#[tokio::test]
async fn idp_issuer_url_non_https_rejected() {
    let (mgr, app, _dir) = setup().await;
    create_org(&mgr, "idp-org2").await;

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/idp-org2/idps",
            Some(json!({
                "issuer_url": "http://insecure.example.com/realms/test",
                "client_id": "peat",
                "client_secret": "secret"
            })),
        ))
        .await
        .unwrap();

    // http:// should be rejected; OIDC issuers should be HTTPS
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "non-HTTPS issuer_url should be rejected"
    );
}
