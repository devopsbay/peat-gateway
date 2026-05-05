//! Cross-tenant isolation test suite.
//!
//! Proves that org A cannot read, modify, or receive events intended for org B.
//! Every org-scoped endpoint is tested with cross-org resource IDs to verify
//! 404 (not 403) responses and no data leakage.

#![cfg(feature = "webhook")]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::Router;
use peat_gateway::api;
use peat_gateway::cdc::CdcEngine;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::models::CdcEvent;
use peat_gateway::tenant::TenantManager;
use reqwest::Client;
use serde_json::{json, Value};
use tokio::sync::Mutex;

// ── Fixtures ─────────────────────────────────────────────────────

struct OrgFixture {
    org_id: String,
    app_id: String,
    token_id: String,
    sink_id: String,
    idp_id: String,
    rule_id: String,
}

/// Spin up a gateway with KEK, two populated orgs, and return everything needed
/// for cross-org probing.
async fn spawn_two_orgs() -> (Client, String, OrgFixture, OrgFixture, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("isolation.redb");

    let config = GatewayConfig {
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
        kek: Some("aa".repeat(32)),
        kms_key_arn: None,
        vault_addr: None,
        vault_token: None,
        vault_transit_key: None,
        mesh_brokers: vec![],
        mesh_poll_interval_ms: 5_000,
    };

    let tenant_mgr = TenantManager::new(&config).await.unwrap();
    let app = api::app(tenant_mgr);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let client = Client::new();
    let base = format!("http://{addr}");

    let alpha = populate_org(&client, &base, "alpha", "mesh-alpha").await;
    let bravo = populate_org(&client, &base, "bravo", "mesh-bravo").await;

    (client, base, alpha, bravo, dir)
}

async fn populate_org(client: &Client, base: &str, org_id: &str, app_id: &str) -> OrgFixture {
    // Create org
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": org_id, "display_name": org_id}))
        .send()
        .await
        .unwrap();

    // Create formation with Open enrollment
    client
        .post(format!("{base}/orgs/{org_id}/formations"))
        .json(&json!({"app_id": app_id, "enrollment_policy": "Open"}))
        .send()
        .await
        .unwrap();

    // Create enrollment token
    let resp = client
        .post(format!("{base}/orgs/{org_id}/tokens"))
        .json(&json!({"app_id": app_id, "label": format!("{org_id}-tok")}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let token_id = body["token_id"].as_str().unwrap().to_string();

    // Create webhook sink (pointing at localhost:1 — won't deliver, that's fine)
    let resp = client
        .post(format!("{base}/orgs/{org_id}/sinks"))
        .json(&json!({"sink_type": {"Webhook": {"url": "http://127.0.0.1:1/hook"}}}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let sink_id = body["sink_id"].as_str().unwrap().to_string();

    // Create IdP config
    let resp = client
        .post(format!("{base}/orgs/{org_id}/idps"))
        .json(&json!({
            "issuer_url": format!("https://idp.{org_id}.example.com"),
            "client_id": format!("{org_id}-client"),
            "client_secret": format!("{org_id}-secret")
        }))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let idp_id = body["idp_id"].as_str().unwrap().to_string();

    // Create policy rule
    let resp = client
        .post(format!("{base}/orgs/{org_id}/policy-rules"))
        .json(&json!({
            "claim_key": "role",
            "claim_value": format!("{org_id}-admin"),
            "tier": "Infrastructure",
            "permissions": 255
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "create policy rule for {org_id}"
    );
    let body: Value = resp.json().await.unwrap();
    let rule_id = body["rule_id"].as_str().unwrap().to_string();

    // Enroll once (populates audit log and certificates)
    let device = peat_mesh::security::DeviceKeypair::generate();
    let pk_hex = hex::encode(device.public_key_bytes());
    client
        .post(format!("{base}/orgs/{org_id}/formations/{app_id}/enroll"))
        .json(&json!({
            "public_key": pk_hex,
            "node_id": format!("{org_id}-node-1")
        }))
        .send()
        .await
        .unwrap();

    OrgFixture {
        org_id: org_id.into(),
        app_id: app_id.into(),
        token_id,
        sink_id,
        idp_id,
        rule_id,
    }
}

// ── Mock webhook server for CDC tests ────────────────────────────

#[derive(Clone)]
struct WebhookState {
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl WebhookState {
    fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

async fn webhook_handler(State(state): State<WebhookState>, body: Bytes) -> StatusCode {
    state.requests.lock().await.push(body.to_vec());
    StatusCode::OK
}

async fn start_webhook(state: WebhookState) -> (String, WebhookState) {
    let app = Router::new()
        .route("/hook", post(webhook_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook"), state)
}

// ── 1. Storage layer: cross-org reads return 404 ─────────────────

#[tokio::test]
async fn storage_layer_cross_org_reads_return_404() {
    let (client, base, alpha, bravo, _dir) = spawn_two_orgs().await;

    // Alpha's formation via bravo's namespace
    let resp = client
        .get(format!(
            "{base}/orgs/{}/formations/{}",
            bravo.org_id, alpha.app_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "cross-org formation GET"
    );

    // Alpha's token via bravo's namespace
    let resp = client
        .get(format!(
            "{base}/orgs/{}/tokens/{}",
            bravo.org_id, alpha.token_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "cross-org token GET");

    // Alpha's sink via bravo's namespace
    let resp = client
        .get(format!(
            "{base}/orgs/{}/sinks/{}",
            bravo.org_id, alpha.sink_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "cross-org sink GET");

    // Alpha's IdP via bravo's namespace
    let resp = client
        .get(format!(
            "{base}/orgs/{}/idps/{}",
            bravo.org_id, alpha.idp_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "cross-org IdP GET");

    // Alpha's formation tokens via bravo's namespace
    let resp = client
        .get(format!(
            "{base}/orgs/{}/formations/{}/tokens",
            bravo.org_id, alpha.app_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "cross-org formation tokens"
    );
}

// ── 2. Storage layer: lists show only own data ───────────────────

#[tokio::test]
async fn storage_layer_cross_org_lists_show_only_own_data() {
    let (client, base, alpha, bravo, _dir) = spawn_two_orgs().await;

    // Formations
    let resp = client
        .get(format!("{base}/orgs/{}/formations", alpha.org_id))
        .send()
        .await
        .unwrap();
    let formations: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(formations.len(), 1);
    assert_eq!(formations[0]["app_id"], alpha.app_id);

    let resp = client
        .get(format!("{base}/orgs/{}/formations", bravo.org_id))
        .send()
        .await
        .unwrap();
    let formations: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(formations.len(), 1);
    assert_eq!(formations[0]["app_id"], bravo.app_id);

    // Sinks
    let resp = client
        .get(format!("{base}/orgs/{}/sinks", alpha.org_id))
        .send()
        .await
        .unwrap();
    let sinks: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(sinks.len(), 1);
    assert_eq!(sinks[0]["sink_id"], alpha.sink_id);

    let resp = client
        .get(format!("{base}/orgs/{}/sinks", bravo.org_id))
        .send()
        .await
        .unwrap();
    let sinks: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(sinks.len(), 1);
    assert_eq!(sinks[0]["sink_id"], bravo.sink_id);

    // IdPs
    let resp = client
        .get(format!("{base}/orgs/{}/idps", alpha.org_id))
        .send()
        .await
        .unwrap();
    let idps: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(idps.len(), 1);
    assert_eq!(idps[0]["idp_id"], alpha.idp_id);

    let resp = client
        .get(format!("{base}/orgs/{}/idps", bravo.org_id))
        .send()
        .await
        .unwrap();
    let idps: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(idps.len(), 1);
    assert_eq!(idps[0]["idp_id"], bravo.idp_id);

    // Policy rules
    let resp = client
        .get(format!("{base}/orgs/{}/policy-rules", alpha.org_id))
        .send()
        .await
        .unwrap();
    let rules: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["rule_id"], alpha.rule_id);

    let resp = client
        .get(format!("{base}/orgs/{}/policy-rules", bravo.org_id))
        .send()
        .await
        .unwrap();
    let rules: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0]["rule_id"], bravo.rule_id);
}

// ── 3. API layer: all cross-org access is 404, never 403 ────────

#[tokio::test]
async fn api_layer_cross_org_returns_404_not_403() {
    let (client, base, alpha, bravo, _dir) = spawn_two_orgs().await;

    let probes = vec![
        (
            "GET formation",
            client
                .get(format!(
                    "{base}/orgs/{}/formations/{}",
                    bravo.org_id, alpha.app_id
                ))
                .build()
                .unwrap(),
        ),
        (
            "GET token",
            client
                .get(format!(
                    "{base}/orgs/{}/tokens/{}",
                    bravo.org_id, alpha.token_id
                ))
                .build()
                .unwrap(),
        ),
        (
            "GET sink",
            client
                .get(format!(
                    "{base}/orgs/{}/sinks/{}",
                    bravo.org_id, alpha.sink_id
                ))
                .build()
                .unwrap(),
        ),
        (
            "GET idp",
            client
                .get(format!(
                    "{base}/orgs/{}/idps/{}",
                    bravo.org_id, alpha.idp_id
                ))
                .build()
                .unwrap(),
        ),
        (
            "DELETE formation",
            client
                .delete(format!(
                    "{base}/orgs/{}/formations/{}",
                    bravo.org_id, alpha.app_id
                ))
                .build()
                .unwrap(),
        ),
        (
            "DELETE token",
            client
                .delete(format!(
                    "{base}/orgs/{}/tokens/{}",
                    bravo.org_id, alpha.token_id
                ))
                .build()
                .unwrap(),
        ),
        (
            "DELETE sink",
            client
                .delete(format!(
                    "{base}/orgs/{}/sinks/{}",
                    bravo.org_id, alpha.sink_id
                ))
                .build()
                .unwrap(),
        ),
        (
            "DELETE idp",
            client
                .delete(format!(
                    "{base}/orgs/{}/idps/{}",
                    bravo.org_id, alpha.idp_id
                ))
                .build()
                .unwrap(),
        ),
        (
            "DELETE policy-rule",
            client
                .delete(format!(
                    "{base}/orgs/{}/policy-rules/{}",
                    bravo.org_id, alpha.rule_id
                ))
                .build()
                .unwrap(),
        ),
    ];

    for (label, req) in probes {
        let resp = client.execute(req).await.unwrap();
        let status = resp.status();
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{label}: expected 404, got {status}"
        );
        assert_ne!(status, StatusCode::FORBIDDEN, "{label}: must never be 403");
    }
}

// ── 4. Negative mutations: cross-org writes fail, originals intact ──

#[tokio::test]
async fn negative_cross_org_mutations_fail() {
    let (client, base, alpha, bravo, _dir) = spawn_two_orgs().await;

    // Try to toggle alpha's sink via bravo
    let resp = client
        .patch(format!(
            "{base}/orgs/{}/sinks/{}",
            bravo.org_id, alpha.sink_id
        ))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "cross-org sink toggle"
    );

    // Try to toggle alpha's IdP via bravo
    let resp = client
        .patch(format!(
            "{base}/orgs/{}/idps/{}",
            bravo.org_id, alpha.idp_id
        ))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND, "cross-org IdP toggle");

    // Verify alpha's originals are intact
    let resp = client
        .get(format!(
            "{base}/orgs/{}/sinks/{}",
            alpha.org_id, alpha.sink_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], true, "alpha sink should still be enabled");

    let resp = client
        .get(format!(
            "{base}/orgs/{}/idps/{}",
            alpha.org_id, alpha.idp_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], true, "alpha IdP should still be enabled");

    // Try to delete alpha's formation via bravo
    let resp = client
        .delete(format!(
            "{base}/orgs/{}/formations/{}",
            bravo.org_id, alpha.app_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "cross-org formation delete"
    );

    // Alpha's formation still exists
    let resp = client
        .get(format!(
            "{base}/orgs/{}/formations/{}",
            alpha.org_id, alpha.app_id
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "alpha formation should survive"
    );
}

// ── 5. CDC layer: events routed only to correct org ──────────────

#[tokio::test]
async fn cdc_layer_cross_org_event_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("cdc-iso.redb");

    let config = GatewayConfig {
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
    };

    let tenant_mgr = TenantManager::new(&config).await.unwrap();
    let cdc_engine = CdcEngine::new(&config, tenant_mgr.clone()).await.unwrap();

    // Set up two webhook receivers
    let alpha_state = WebhookState::new();
    let (alpha_url, alpha_state) = start_webhook(alpha_state).await;
    let bravo_state = WebhookState::new();
    let (bravo_url, bravo_state) = start_webhook(bravo_state).await;

    // Create orgs with webhook sinks pointing to their respective receivers
    use peat_gateway::tenant::models::{CdcSinkType, EnrollmentPolicy};

    tenant_mgr
        .create_org("alpha".into(), "Alpha Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("alpha", "mesh-alpha".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink("alpha", CdcSinkType::Webhook { url: alpha_url })
        .await
        .unwrap();

    tenant_mgr
        .create_org("bravo".into(), "Bravo Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("bravo", "mesh-bravo".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink("bravo", CdcSinkType::Webhook { url: bravo_url })
        .await
        .unwrap();

    // Publish event for alpha
    let alpha_event = CdcEvent {
        org_id: "alpha".into(),
        app_id: "mesh-alpha".into(),
        document_id: "doc-secret".into(),
        change_hash: "hash-alpha".into(),
        actor_id: "peer-a".into(),
        timestamp_ms: 1700000000000,
        patches: json!({"classified": true}),
    };
    cdc_engine.publish(&alpha_event).await.unwrap();

    // Alpha received it, bravo did not
    let alpha_reqs = alpha_state.requests.lock().await;
    let bravo_reqs = bravo_state.requests.lock().await;
    assert_eq!(alpha_reqs.len(), 1, "alpha should receive its event");
    assert_eq!(bravo_reqs.len(), 0, "bravo must NOT receive alpha's event");

    // Verify the event contents match alpha
    let received: CdcEvent = serde_json::from_slice(&alpha_reqs[0]).unwrap();
    assert_eq!(received.org_id, "alpha");
    assert_eq!(received.document_id, "doc-secret");
    drop(alpha_reqs);
    drop(bravo_reqs);

    // Now publish for bravo
    let bravo_event = CdcEvent {
        org_id: "bravo".into(),
        app_id: "mesh-bravo".into(),
        document_id: "doc-other".into(),
        change_hash: "hash-bravo".into(),
        actor_id: "peer-b".into(),
        timestamp_ms: 1700000000001,
        patches: json!(null),
    };
    cdc_engine.publish(&bravo_event).await.unwrap();

    let alpha_reqs = alpha_state.requests.lock().await;
    let bravo_reqs = bravo_state.requests.lock().await;
    assert_eq!(alpha_reqs.len(), 1, "alpha should still have only 1 event");
    assert_eq!(bravo_reqs.len(), 1, "bravo should receive its event");

    let received: CdcEvent = serde_json::from_slice(&bravo_reqs[0]).unwrap();
    assert_eq!(received.org_id, "bravo");
    assert_eq!(received.document_id, "doc-other");
}

// ── 6. Identity layer: certificates have distinct mesh IDs ───────

#[tokio::test]
async fn identity_layer_cross_org_certificate_isolation() {
    let (client, base, alpha, bravo, _dir) = spawn_two_orgs().await;

    // Enroll fresh devices in each org's formation
    let device_a = peat_mesh::security::DeviceKeypair::generate();
    let pk_a = hex::encode(device_a.public_key_bytes());
    let resp = client
        .post(format!(
            "{base}/orgs/{}/formations/{}/enroll",
            alpha.org_id, alpha.app_id
        ))
        .json(&json!({"public_key": pk_a, "node_id": "iso-node-a"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_a: Value = resp.json().await.unwrap();

    let device_b = peat_mesh::security::DeviceKeypair::generate();
    let pk_b = hex::encode(device_b.public_key_bytes());
    let resp = client
        .post(format!(
            "{base}/orgs/{}/formations/{}/enroll",
            bravo.org_id, bravo.app_id
        ))
        .json(&json!({"public_key": pk_b, "node_id": "iso-node-b"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_b: Value = resp.json().await.unwrap();

    // Both should have certificates
    assert!(
        body_a["certificate"].is_string(),
        "alpha should get a certificate"
    );
    assert!(
        body_b["certificate"].is_string(),
        "bravo should get a certificate"
    );

    // Mesh IDs must differ (each formation has its own genesis)
    let mesh_id_a = body_a["mesh_id"].as_str().unwrap();
    let mesh_id_b = body_b["mesh_id"].as_str().unwrap();
    assert_ne!(
        mesh_id_a, mesh_id_b,
        "formations in different orgs must have distinct mesh IDs"
    );

    // Authority public keys must differ (each genesis has its own signing key)
    let auth_a = body_a["authority_public_key"].as_str().unwrap();
    let auth_b = body_b["authority_public_key"].as_str().unwrap();
    assert_ne!(
        auth_a, auth_b,
        "authority keys must be distinct across orgs"
    );

    // Cross-org enrollment must fail: alpha's device enrolling in bravo's formation
    let resp = client
        .post(format!(
            "{base}/orgs/{}/formations/{}/enroll",
            bravo.org_id, alpha.app_id
        ))
        .json(&json!({"public_key": pk_a, "node_id": "cross-node"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "cross-org formation enrollment should fail"
    );
}

// ── 7. Audit log: scoped to own org ──────────────────────────────

#[tokio::test]
async fn audit_log_cross_org_isolation() {
    let (client, base, alpha, bravo, _dir) = spawn_two_orgs().await;

    // Alpha's audit log should only contain alpha entries
    let resp = client
        .get(format!("{base}/orgs/{}/audit?limit=100", alpha.org_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert!(!entries.is_empty(), "alpha should have audit entries");
    for entry in &entries {
        assert_eq!(
            entry["org_id"].as_str().unwrap(),
            "alpha",
            "alpha audit log must not contain other org entries"
        );
    }

    // Bravo's audit log should only contain bravo entries
    let resp = client
        .get(format!("{base}/orgs/{}/audit?limit=100", bravo.org_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let entries: Vec<Value> = resp.json().await.unwrap();
    assert!(!entries.is_empty(), "bravo should have audit entries");
    for entry in &entries {
        assert_eq!(
            entry["org_id"].as_str().unwrap(),
            "bravo",
            "bravo audit log must not contain other org entries"
        );
    }
}
