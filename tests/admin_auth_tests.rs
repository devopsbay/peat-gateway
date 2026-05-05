use std::net::SocketAddr;

use peat_gateway::api;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::TenantManager;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

const ADMIN_TOKEN: &str = "test-admin-secret-token";

/// Spawn a gateway with admin auth enabled.
async fn spawn_authenticated() -> (Client, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

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
        admin_token: Some(ADMIN_TOKEN.into()),
        kek: None,
        kms_key_arn: None,
        vault_addr: None,
        vault_token: None,
        vault_transit_key: None,
        mesh_brokers: vec![],
        mesh_poll_interval_ms: 5_000,
    };

    let tenant_mgr = TenantManager::new(&config).await.unwrap();
    let app = api::app_authenticated(tenant_mgr, Some(ADMIN_TOKEN.into()));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let base = format!("http://{}", addr);
    (client, base, dir)
}

/// Spawn a gateway without admin auth (dev mode).
async fn spawn_unauthenticated() -> (Client, String, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

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
    let app = api::app(tenant_mgr);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let base = format!("http://{}", addr);
    (client, base, dir)
}

// ── Auth required: missing token ────────────────────────────────

#[tokio::test]
async fn admin_no_token_returns_401() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client.get(format!("{base}/orgs")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Admin token required");
}

#[tokio::test]
async fn admin_wrong_token_returns_403() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client
        .get(format!("{base}/orgs"))
        .bearer_auth("wrong-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["error"], "Invalid admin token");
}

#[tokio::test]
async fn admin_correct_token_allows_access() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client
        .get(format!("{base}/orgs"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.unwrap();
    assert!(body.as_array().unwrap().is_empty());
}

// ── Auth required: write operations ─────────────────────────────

#[tokio::test]
async fn create_org_requires_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    // Without token → 401
    let resp = client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme Corp"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // With token → 200
    let resp = client
        .post(format!("{base}/orgs"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"org_id": "acme", "display_name": "Acme Corp"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn delete_org_requires_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    // Create org first
    client
        .post(format!("{base}/orgs"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"org_id": "temp", "display_name": "Temp"}))
        .send()
        .await
        .unwrap();

    // Delete without token → 401
    let resp = client
        .delete(format!("{base}/orgs/temp"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Delete with token → 200
    let resp = client
        .delete(format!("{base}/orgs/temp"))
        .bearer_auth(ADMIN_TOKEN)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Auth covers all admin route groups ──────────────────────────

#[tokio::test]
async fn tokens_endpoint_requires_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    // Setup: create org + formation
    client
        .post(format!("{base}/orgs"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/orgs/acme/formations"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"app_id": "mesh-a"}))
        .send()
        .await
        .unwrap();

    // Token creation without auth → 401
    let resp = client
        .post(format!("{base}/orgs/acme/tokens"))
        .json(&json!({"app_id": "mesh-a", "label": "test"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn sinks_endpoint_requires_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client
        .get(format!("{base}/orgs/acme/sinks"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn idps_endpoint_requires_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client
        .get(format!("{base}/orgs/acme/idps"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn audit_endpoint_requires_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client
        .get(format!("{base}/orgs/acme/audit"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn formations_endpoint_requires_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client
        .get(format!("{base}/orgs/acme/formations"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn policy_rules_endpoint_requires_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client
        .get(format!("{base}/orgs/acme/policy-rules"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Public routes remain open ───────────────────────────────────

#[tokio::test]
async fn health_does_not_require_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn metrics_does_not_require_auth() {
    let (client, base, _dir) = spawn_authenticated().await;

    let resp = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Dev mode (no token configured) ─────────────────────────────

#[tokio::test]
async fn dev_mode_allows_unauthenticated_admin_access() {
    let (client, base, _dir) = spawn_unauthenticated().await;

    let resp = client.get(format!("{base}/orgs")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn dev_mode_create_org_works_without_token() {
    let (client, base, _dir) = spawn_unauthenticated().await;

    let resp = client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme Corp"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
