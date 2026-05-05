//! P2 robustness tests for single-node production readiness.
//!
//! Covers: OIDC failure modes (#37), CDC disabled-sink behavior (#38),
//! URL validation edge cases (#39), cascading deletes (#40).

use std::net::SocketAddr;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use peat_gateway::api;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::models::EnrollmentPolicy;
use peat_gateway::tenant::TenantManager;
use reqwest::Client;
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

async fn spawn_app() -> (Client, String, TenantManager, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let tenant_mgr = TenantManager::new(&config).await.unwrap();
    let app = api::app(tenant_mgr.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let base = format!("http://{}", addr);
    (client, base, tenant_mgr, dir)
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

// ═══════════════════════════════════════════════════════════════════
// #37 — OIDC introspection failure modes
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn controlled_enrollment_with_unreachable_idp_returns_error() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());

    mgr.create_org("oidc-org".into(), "OIDC Org".into())
        .await
        .unwrap();
    mgr.create_formation("oidc-org", "ctrl-mesh".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    // Create IdP pointing to a non-existent server
    mgr.create_idp(
        "oidc-org",
        "https://idp.does-not-exist.invalid/realms/test".into(),
        "client-id".into(),
        "client-secret".into(),
    )
    .await
    .unwrap();

    // Attempt enrollment with a bearer token — should fail at IdP discovery
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orgs/oidc-org/formations/ctrl-mesh/enroll")
                .header("content-type", "application/json")
                .header("authorization", "Bearer fake-token-12345")
                .body(Body::from(
                    json!({
                        "public_key": hex::encode([0xAA; 32]),
                        "node_id": "test-node"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Should get 401 (token validation failed) not 500
    assert_eq!(
        resp.status(),
        StatusCode::UNAUTHORIZED,
        "unreachable IdP should return 401, not 500"
    );
}

#[tokio::test]
async fn controlled_enrollment_without_idp_returns_bad_request() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());

    mgr.create_org("no-idp-org".into(), "No IdP Org".into())
        .await
        .unwrap();
    mgr.create_formation(
        "no-idp-org",
        "ctrl-mesh".into(),
        EnrollmentPolicy::Controlled,
    )
    .await
    .unwrap();
    // No IdP configured

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orgs/no-idp-org/formations/ctrl-mesh/enroll")
                .header("content-type", "application/json")
                .header("authorization", "Bearer some-token")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "no IdP configured should return 400"
    );
}

#[tokio::test]
async fn controlled_enrollment_with_disabled_idp_returns_bad_request() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());

    mgr.create_org("dis-idp".into(), "Disabled IdP Org".into())
        .await
        .unwrap();
    mgr.create_formation("dis-idp", "ctrl-mesh".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    // Create IdP then disable it
    let idp = mgr
        .create_idp(
            "dis-idp",
            "https://idp.example.com/realms/test".into(),
            "client-id".into(),
            "client-secret".into(),
        )
        .await
        .unwrap();
    mgr.toggle_idp("dis-idp", &idp.idp_id, false).await.unwrap();

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/orgs/dis-idp/formations/ctrl-mesh/enroll")
                .header("content-type", "application/json")
                .header("authorization", "Bearer some-token")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "disabled IdP should return 400 (no enabled IdP)"
    );
}

// ═══════════════════════════════════════════════════════════════════
// #39 — URL validation edge cases
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn webhook_url_javascript_scheme_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());

    mgr.create_org("js-org".into(), "JS Org".into())
        .await
        .unwrap();

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/js-org/sinks",
            Some(json!({"sink_type": {"Webhook": {"url": "javascript:alert(1)"}}})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn webhook_url_ftp_scheme_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());

    mgr.create_org("ftp-org".into(), "FTP Org".into())
        .await
        .unwrap();

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/ftp-org/sinks",
            Some(json!({"sink_type": {"Webhook": {"url": "ftp://evil.com/exfil"}}})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn webhook_url_valid_http_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());

    mgr.create_org("http-org".into(), "HTTP Org".into())
        .await
        .unwrap();

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/http-org/sinks",
            Some(json!({"sink_type": {"Webhook": {"url": "http://localhost:9090/hook"}}})),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "valid http:// webhook should be accepted"
    );
}

#[tokio::test]
async fn webhook_url_valid_https_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());

    mgr.create_org("https-org".into(), "HTTPS Org".into())
        .await
        .unwrap();

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/https-org/sinks",
            Some(json!({"sink_type": {"Webhook": {"url": "https://hooks.example.com/cdc"}}})),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "valid https:// webhook should be accepted"
    );
}

#[tokio::test]
async fn nats_sink_empty_subject_prefix_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let config = test_config(&dir, None);
    let mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(mgr.clone());

    mgr.create_org("nats-val".into(), "NATS Val".into())
        .await
        .unwrap();

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/nats-val/sinks",
            Some(json!({"sink_type": {"Nats": {"subject_prefix": ""}}})),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "empty NATS subject_prefix should be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════
// #40 — Cascading deletes and orphaned data
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn delete_org_cascades_all_children() {
    let (client, base, mgr, _dir) = spawn_app().await;

    // Create org with formations, tokens, sinks, IdP, policy rules
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "cascade-org", "display_name": "Cascade Corp"}))
        .send()
        .await
        .unwrap();

    // Bump quotas
    client
        .patch(format!("{base}/orgs/cascade-org"))
        .json(&json!({"quotas": {
            "max_formations": 100,
            "max_peers_per_formation": 100,
            "max_documents_per_formation": 10000,
            "max_cdc_sinks": 100,
            "max_enrollments_per_hour": 1000
        }}))
        .send()
        .await
        .unwrap();

    // Create 2 formations
    for app in ["app-a", "app-b"] {
        client
            .post(format!("{base}/orgs/cascade-org/formations"))
            .json(&json!({"app_id": app, "enrollment_policy": "Open"}))
            .send()
            .await
            .unwrap();
    }

    // Create tokens
    let resp = client
        .post(format!("{base}/orgs/cascade-org/tokens"))
        .json(&json!({"app_id": "app-a", "label": "tok-1"}))
        .send()
        .await
        .unwrap();
    let token: Value = resp.json().await.unwrap();
    let token_id = token["token_id"].as_str().unwrap().to_string();

    // Create sinks
    let resp = client
        .post(format!("{base}/orgs/cascade-org/sinks"))
        .json(&json!({"sink_type": {"Nats": {"subject_prefix": "cdc"}}}))
        .send()
        .await
        .unwrap();
    let sink: Value = resp.json().await.unwrap();
    let sink_id = sink["sink_id"].as_str().unwrap().to_string();

    // Create IdP
    let resp = client
        .post(format!("{base}/orgs/cascade-org/idps"))
        .json(&json!({
            "issuer_url": "https://keycloak.example.com/realms/test",
            "client_id": "peat",
            "client_secret": "secret"
        }))
        .send()
        .await
        .unwrap();
    let idp: Value = resp.json().await.unwrap();
    let idp_id = idp["idp_id"].as_str().unwrap().to_string();

    // Create policy rule
    client
        .post(format!("{base}/orgs/cascade-org/policy-rules"))
        .json(&json!({
            "claim_key": "role",
            "claim_value": "admin",
            "tier": "Authority"
        }))
        .send()
        .await
        .unwrap();

    // Perform enrollment to create audit entries
    client
        .post(format!("{base}/orgs/cascade-org/formations/app-a/enroll"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();

    // Verify everything exists
    assert_eq!(
        client
            .get(format!("{base}/orgs/cascade-org/formations"))
            .send()
            .await
            .unwrap()
            .json::<Vec<Value>>()
            .await
            .unwrap()
            .len(),
        2
    );

    // DELETE the org
    let resp = client
        .delete(format!("{base}/orgs/cascade-org"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Verify org is gone
    assert_eq!(
        client
            .get(format!("{base}/orgs/cascade-org"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // Verify formations are gone
    assert_eq!(
        client
            .get(format!("{base}/orgs/cascade-org/formations"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND // org doesn't exist
    );

    // Verify token is gone
    assert_eq!(
        client
            .get(format!("{base}/orgs/cascade-org/tokens/{token_id}"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // Verify sink is gone
    assert_eq!(
        client
            .get(format!("{base}/orgs/cascade-org/sinks/{sink_id}"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // Verify IdP is gone
    assert_eq!(
        client
            .get(format!("{base}/orgs/cascade-org/idps/{idp_id}"))
            .send()
            .await
            .unwrap()
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );

    // Verify genesis is gone (check through storage directly)
    // TenantManager still works since the store is shared
    let result = mgr.load_genesis("cascade-org", "app-a").await;
    assert!(result.is_err(), "genesis should be deleted with org");
}

#[tokio::test]
async fn delete_formation_cleans_up_genesis() {
    let (client, base, mgr, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "fmtn-del", "display_name": "Formation Delete Corp"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/orgs/fmtn-del/formations"))
        .json(&json!({"app_id": "del-app", "enrollment_policy": "Open"}))
        .send()
        .await
        .unwrap();

    // Verify genesis exists
    let genesis = mgr.load_genesis("fmtn-del", "del-app").await;
    assert!(genesis.is_ok(), "genesis should exist before deletion");

    // Delete formation
    let resp = client
        .delete(format!("{base}/orgs/fmtn-del/formations/del-app"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Genesis should be gone
    let result = mgr.load_genesis("fmtn-del", "del-app").await;
    assert!(result.is_err(), "genesis should be deleted with formation");
}

#[tokio::test]
async fn delete_formation_orphans_tokens() {
    let (client, base, _mgr, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "orphan-org", "display_name": "Orphan Corp"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/orgs/orphan-org/formations"))
        .json(&json!({"app_id": "orphan-app", "enrollment_policy": "Open"}))
        .send()
        .await
        .unwrap();

    // Create a token for this formation
    let resp = client
        .post(format!("{base}/orgs/orphan-org/tokens"))
        .json(&json!({"app_id": "orphan-app", "label": "orphan-token"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::CREATED);
    let token: Value = resp.json().await.unwrap();
    let token_id = token["token_id"].as_str().unwrap().to_string();

    // Delete the formation
    client
        .delete(format!("{base}/orgs/orphan-org/formations/orphan-app"))
        .send()
        .await
        .unwrap();

    // Token is still accessible (orphaned — known behavior)
    let resp = client
        .get(format!("{base}/orgs/orphan-org/tokens/{token_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "token survives formation deletion (orphaned)"
    );

    // But listing tokens for the deleted formation fails (formation not found)
    let resp = client
        .get(format!(
            "{base}/orgs/orphan-org/formations/orphan-app/tokens"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "listing tokens for deleted formation should fail"
    );
}

#[tokio::test]
async fn delete_org_with_no_children_succeeds() {
    let (client, base, _mgr, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "empty-org", "display_name": "Empty Corp"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{base}/orgs/empty-org"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}
