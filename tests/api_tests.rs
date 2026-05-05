use std::net::SocketAddr;

use peat_gateway::api;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::TenantManager;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

/// Spin up the full Axum server on a random port backed by a temp redb.
/// Returns the HTTP client and base URL.
async fn spawn_app() -> (Client, String, tempfile::TempDir) {
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

// ── Health ──────────────────────────────────────────────────────

#[tokio::test]
async fn health_returns_ok() {
    let (client, base, _dir) = spawn_app().await;

    let resp = client.get(format!("{base}/health")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
}

#[tokio::test]
async fn metrics_returns_ok() {
    let (client, base, _dir) = spawn_app().await;

    let resp = client.get(format!("{base}/metrics")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Org CRUD ────────────────────────────────────────────────────

#[tokio::test]
async fn create_and_get_org() {
    let (client, base, _dir) = spawn_app().await;

    // Create
    let resp = client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme Corp"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["org_id"], "acme");
    assert_eq!(body["display_name"], "Acme Corp");
    assert!(body["created_at"].is_number());
    assert_eq!(body["quotas"]["max_formations"], 10);

    // Get
    let resp = client
        .get(format!("{base}/orgs/acme"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["org_id"], "acme");
}

#[tokio::test]
async fn list_orgs_empty_then_populated() {
    let (client, base, _dir) = spawn_app().await;

    // Empty
    let resp = client.get(format!("{base}/orgs")).send().await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Vec<Value> = resp.json().await.unwrap();
    assert!(body.is_empty());

    // Create two
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "alpha", "display_name": "Alpha"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "bravo", "display_name": "Bravo"}))
        .send()
        .await
        .unwrap();

    // List
    let resp = client.get(format!("{base}/orgs")).send().await.unwrap();
    let body: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(body.len(), 2);
}

#[tokio::test]
async fn create_duplicate_org_returns_400() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme Again"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_nonexistent_org_returns_404() {
    let (client, base, _dir) = spawn_app().await;

    let resp = client
        .get(format!("{base}/orgs/ghost"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn update_org() {
    let (client, base, _dir) = spawn_app().await;

    // Create
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    // Update display_name only
    let resp = client
        .patch(format!("{base}/orgs/acme"))
        .json(&json!({"display_name": "Acme Corp Updated"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["display_name"], "Acme Corp Updated");
    // quotas unchanged
    assert_eq!(body["quotas"]["max_formations"], 10);

    // Update quotas only
    let resp = client
        .patch(format!("{base}/orgs/acme"))
        .json(&json!({
            "quotas": {
                "max_formations": 50,
                "max_peers_per_formation": 200,
                "max_documents_per_formation": 20000,
                "max_cdc_sinks": 10
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["display_name"], "Acme Corp Updated");
    assert_eq!(body["quotas"]["max_formations"], 50);

    // Verify via GET
    let resp = client
        .get(format!("{base}/orgs/acme"))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["display_name"], "Acme Corp Updated");
    assert_eq!(body["quotas"]["max_formations"], 50);
}

#[tokio::test]
async fn update_nonexistent_org_returns_404() {
    let (client, base, _dir) = spawn_app().await;

    let resp = client
        .patch(format!("{base}/orgs/ghost"))
        .json(&json!({"display_name": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_org() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{base}/orgs/acme"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Gone
    let resp = client
        .get(format!("{base}/orgs/acme"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_nonexistent_org_returns_404() {
    let (client, base, _dir) = spawn_app().await;

    let resp = client
        .delete(format!("{base}/orgs/ghost"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Formation CRUD ──────────────────────────────────────────────

#[tokio::test]
async fn create_and_get_formation() {
    let (client, base, _dir) = spawn_app().await;

    // Org first
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    // Create formation
    let resp = client
        .post(format!("{base}/orgs/acme/formations"))
        .json(&json!({"app_id": "logistics"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["app_id"], "logistics");
    assert_eq!(body["enrollment_policy"], "Controlled"); // default
    assert!(body["mesh_id"].is_string());
    assert_eq!(body["mesh_id"].as_str().unwrap().len(), 8); // 4 bytes hex

    // Get
    let resp = client
        .get(format!("{base}/orgs/acme/formations/logistics"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let get_body: Value = resp.json().await.unwrap();
    assert_eq!(get_body["app_id"], "logistics");
    assert_eq!(get_body["mesh_id"], body["mesh_id"]);
}

#[tokio::test]
async fn create_formation_with_explicit_policy() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs/acme/formations"))
        .json(&json!({"app_id": "secure-mesh", "enrollment_policy": "Strict"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["enrollment_policy"], "Strict");
}

#[tokio::test]
async fn list_formations() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    // Empty initially
    let resp = client
        .get(format!("{base}/orgs/acme/formations"))
        .send()
        .await
        .unwrap();
    let body: Vec<Value> = resp.json().await.unwrap();
    assert!(body.is_empty());

    // Create two
    for app_id in &["alpha", "bravo"] {
        client
            .post(format!("{base}/orgs/acme/formations"))
            .json(&json!({"app_id": app_id}))
            .send()
            .await
            .unwrap();
    }

    let resp = client
        .get(format!("{base}/orgs/acme/formations"))
        .send()
        .await
        .unwrap();
    let body: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(body.len(), 2);
}

#[tokio::test]
async fn create_duplicate_formation_returns_400() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/orgs/acme/formations"))
        .json(&json!({"app_id": "logistics"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs/acme/formations"))
        .json(&json!({"app_id": "logistics"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn formation_quota_enforcement() {
    let (client, base, _dir) = spawn_app().await;

    // Create org, then update quota to max 2 formations
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    client
        .patch(format!("{base}/orgs/acme"))
        .json(&json!({
            "quotas": {
                "max_formations": 2,
                "max_peers_per_formation": 100,
                "max_documents_per_formation": 10000,
                "max_cdc_sinks": 5
            }
        }))
        .send()
        .await
        .unwrap();

    // Create 2 formations — should succeed
    for app_id in &["one", "two"] {
        let resp = client
            .post(format!("{base}/orgs/acme/formations"))
            .json(&json!({"app_id": app_id}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Third should fail
    let resp = client
        .post(format!("{base}/orgs/acme/formations"))
        .json(&json!({"app_id": "three"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = resp.text().await.unwrap();
    assert!(body.contains("quota"));
}

#[tokio::test]
async fn create_formation_for_nonexistent_org_returns_400() {
    let (client, base, _dir) = spawn_app().await;

    let resp = client
        .post(format!("{base}/orgs/ghost/formations"))
        .json(&json!({"app_id": "nope"}))
        .send()
        .await
        .unwrap();
    // create_formation calls get_org which returns error → bad_request
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_nonexistent_formation_returns_404() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/orgs/acme/formations/ghost"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_formation() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    client
        .post(format!("{base}/orgs/acme/formations"))
        .json(&json!({"app_id": "logistics"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{base}/orgs/acme/formations/logistics"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Gone
    let resp = client
        .get(format!("{base}/orgs/acme/formations/logistics"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_nonexistent_formation_returns_404() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .delete(format!("{base}/orgs/acme/formations/ghost"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Formation isolation across orgs ─────────────────────────────

#[tokio::test]
async fn formations_are_isolated_across_orgs() {
    let (client, base, _dir) = spawn_app().await;

    // Create two orgs
    for org in &["alpha", "bravo"] {
        client
            .post(format!("{base}/orgs"))
            .json(&json!({"org_id": org, "display_name": org}))
            .send()
            .await
            .unwrap();
    }

    // Same app_id in both orgs — should succeed
    for org in &["alpha", "bravo"] {
        let resp = client
            .post(format!("{base}/orgs/{org}/formations"))
            .json(&json!({"app_id": "shared-name"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Each org sees only its own formation
    for org in &["alpha", "bravo"] {
        let resp = client
            .get(format!("{base}/orgs/{org}/formations"))
            .send()
            .await
            .unwrap();
        let body: Vec<Value> = resp.json().await.unwrap();
        assert_eq!(body.len(), 1);
    }

    // Delete alpha's formation doesn't affect bravo
    client
        .delete(format!("{base}/orgs/alpha/formations/shared-name"))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/orgs/bravo/formations/shared-name"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// ── Cascade: deleting org removes its formations ────────────────

#[tokio::test]
async fn delete_org_cascades_formations() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    for app_id in &["mesh-a", "mesh-b", "mesh-c"] {
        client
            .post(format!("{base}/orgs/acme/formations"))
            .json(&json!({"app_id": app_id}))
            .send()
            .await
            .unwrap();
    }

    // Delete org
    client
        .delete(format!("{base}/orgs/acme"))
        .send()
        .await
        .unwrap();

    // Org gone
    let resp = client
        .get(format!("{base}/orgs/acme"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Formations gone (list_formations verifies org exists, so this returns 404)
    let resp = client
        .get(format!("{base}/orgs/acme/formations"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ── Malformed requests ──────────────────────────────────────────

#[tokio::test]
async fn create_org_missing_fields_returns_422() {
    let (client, base, _dir) = spawn_app().await;

    // Missing display_name
    let resp = client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Empty body
    let resp = client
        .post(format!("{base}/orgs"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn create_formation_missing_app_id_returns_422() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs/acme/formations"))
        .header("content-type", "application/json")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

// ── Enrollment Token CRUD ───────────────────────────────────────

/// Helper: create org + formation, return base URL
async fn setup_org_and_formation(client: &Client, base: &str) {
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/orgs/acme/formations"))
        .json(&json!({"app_id": "logistics"}))
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn create_and_get_enrollment_token() {
    let (client, base, _dir) = spawn_app().await;
    setup_org_and_formation(&client, &base).await;

    // Create token
    let resp = client
        .post(format!("{base}/orgs/acme/tokens"))
        .json(&json!({
            "app_id": "logistics",
            "label": "field-team-alpha",
            "max_uses": 10
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["org_id"], "acme");
    assert_eq!(body["app_id"], "logistics");
    assert_eq!(body["label"], "field-team-alpha");
    assert_eq!(body["max_uses"], 10);
    assert_eq!(body["uses"], 0);
    assert_eq!(body["revoked"], false);
    let token_id = body["token_id"].as_str().unwrap().to_string();
    assert!(token_id.starts_with("peat_")); // prefix convention
    assert_eq!(token_id.len(), 37); // "peat_" (5) + 32 hex chars

    // Get token
    let resp = client
        .get(format!("{base}/orgs/acme/tokens/{token_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let get_body: Value = resp.json().await.unwrap();
    assert_eq!(get_body["token_id"], token_id);
}

#[tokio::test]
async fn list_tokens_scoped_to_formation() {
    let (client, base, _dir) = spawn_app().await;
    setup_org_and_formation(&client, &base).await;

    // Create a second formation
    client
        .post(format!("{base}/orgs/acme/formations"))
        .json(&json!({"app_id": "comms"}))
        .send()
        .await
        .unwrap();

    // Token for logistics
    client
        .post(format!("{base}/orgs/acme/tokens"))
        .json(&json!({"app_id": "logistics", "label": "tok-a"}))
        .send()
        .await
        .unwrap();

    // Token for comms
    client
        .post(format!("{base}/orgs/acme/tokens"))
        .json(&json!({"app_id": "comms", "label": "tok-b"}))
        .send()
        .await
        .unwrap();

    // List logistics tokens — should only see 1
    let resp = client
        .get(format!("{base}/orgs/acme/formations/logistics/tokens"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(body.len(), 1);
    assert_eq!(body[0]["label"], "tok-a");
}

#[tokio::test]
async fn revoke_enrollment_token() {
    let (client, base, _dir) = spawn_app().await;
    setup_org_and_formation(&client, &base).await;

    let resp = client
        .post(format!("{base}/orgs/acme/tokens"))
        .json(&json!({"app_id": "logistics", "label": "temp"}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let token_id = body["token_id"].as_str().unwrap();

    // Revoke
    let resp = client
        .post(format!("{base}/orgs/acme/tokens/{token_id}/revoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["revoked"], true);

    // Revoke again — should fail
    let resp = client
        .post(format!("{base}/orgs/acme/tokens/{token_id}/revoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn delete_enrollment_token() {
    let (client, base, _dir) = spawn_app().await;
    setup_org_and_formation(&client, &base).await;

    let resp = client
        .post(format!("{base}/orgs/acme/tokens"))
        .json(&json!({"app_id": "logistics", "label": "disposable"}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let token_id = body["token_id"].as_str().unwrap();

    let resp = client
        .delete(format!("{base}/orgs/acme/tokens/{token_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Gone
    let resp = client
        .get(format!("{base}/orgs/acme/tokens/{token_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn create_token_for_nonexistent_formation_returns_400() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs/acme/tokens"))
        .json(&json!({"app_id": "ghost", "label": "nope"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── CDC Sink CRUD ───────────────────────────────────────────────

#[tokio::test]
async fn create_and_get_cdc_sink() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs/acme/sinks"))
        .json(&json!({
            "sink_type": {"Nats": {"subject_prefix": "peat.acme"}}
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["org_id"], "acme");
    assert_eq!(body["enabled"], true);
    assert!(body["sink_id"].is_string());
    let sink_id = body["sink_id"].as_str().unwrap();

    // Get
    let resp = client
        .get(format!("{base}/orgs/acme/sinks/{sink_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let get_body: Value = resp.json().await.unwrap();
    assert_eq!(get_body["sink_type"]["Nats"]["subject_prefix"], "peat.acme");
}

#[tokio::test]
async fn list_cdc_sinks() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    // Empty
    let resp = client
        .get(format!("{base}/orgs/acme/sinks"))
        .send()
        .await
        .unwrap();
    let body: Vec<Value> = resp.json().await.unwrap();
    assert!(body.is_empty());

    // Create two
    client
        .post(format!("{base}/orgs/acme/sinks"))
        .json(&json!({"sink_type": {"Nats": {"subject_prefix": "peat.acme"}}}))
        .send()
        .await
        .unwrap();
    client
        .post(format!("{base}/orgs/acme/sinks"))
        .json(&json!({"sink_type": {"Webhook": {"url": "https://example.com/hook"}}}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/orgs/acme/sinks"))
        .send()
        .await
        .unwrap();
    let body: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(body.len(), 2);
}

#[tokio::test]
async fn toggle_cdc_sink() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs/acme/sinks"))
        .json(&json!({"sink_type": {"Nats": {"subject_prefix": "peat.acme"}}}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let sink_id = body["sink_id"].as_str().unwrap();
    assert_eq!(body["enabled"], true);

    // Disable
    let resp = client
        .patch(format!("{base}/orgs/acme/sinks/{sink_id}"))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], false);

    // Re-enable
    let resp = client
        .patch(format!("{base}/orgs/acme/sinks/{sink_id}"))
        .json(&json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["enabled"], true);
}

#[tokio::test]
async fn delete_cdc_sink() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs/acme/sinks"))
        .json(&json!({"sink_type": {"Kafka": {"topic": "peat-events"}}}))
        .send()
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    let sink_id = body["sink_id"].as_str().unwrap();

    let resp = client
        .delete(format!("{base}/orgs/acme/sinks/{sink_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Gone
    let resp = client
        .get(format!("{base}/orgs/acme/sinks/{sink_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cdc_sink_quota_enforcement() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    // Set quota to 2
    client
        .patch(format!("{base}/orgs/acme"))
        .json(&json!({
            "quotas": {
                "max_formations": 10,
                "max_peers_per_formation": 100,
                "max_documents_per_formation": 10000,
                "max_cdc_sinks": 2
            }
        }))
        .send()
        .await
        .unwrap();

    // Create 2 — should work
    for i in 0..2 {
        let resp = client
            .post(format!("{base}/orgs/acme/sinks"))
            .json(&json!({"sink_type": {"Nats": {"subject_prefix": format!("peat.{i}")}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    // Third should fail
    let resp = client
        .post(format!("{base}/orgs/acme/sinks"))
        .json(&json!({"sink_type": {"Nats": {"subject_prefix": "peat.overflow"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let text = resp.text().await.unwrap();
    assert!(text.contains("quota"));
}

// ── Stub endpoints (peers, documents, certificates) ─────────────

#[tokio::test]
async fn list_peers_returns_empty() {
    let (client, base, _dir) = spawn_app().await;
    setup_org_and_formation(&client, &base).await;

    let resp = client
        .get(format!("{base}/orgs/acme/formations/logistics/peers"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Vec<Value> = resp.json().await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn list_peers_nonexistent_formation_returns_404() {
    let (client, base, _dir) = spawn_app().await;

    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": "acme", "display_name": "Acme"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .get(format!("{base}/orgs/acme/formations/ghost/peers"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_documents_returns_empty() {
    let (client, base, _dir) = spawn_app().await;
    setup_org_and_formation(&client, &base).await;

    let resp = client
        .get(format!("{base}/orgs/acme/formations/logistics/documents"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Vec<Value> = resp.json().await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn list_certificates_returns_root_cert() {
    let (client, base, _dir) = spawn_app().await;
    setup_org_and_formation(&client, &base).await;

    let resp = client
        .get(format!(
            "{base}/orgs/acme/formations/logistics/certificates"
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Vec<Value> = resp.json().await.unwrap();
    // Should contain at least the root authority certificate
    assert!(!body.is_empty());
    assert_eq!(body[0]["peer_id"], "authority-0");
    assert!(!body[0]["fingerprint"].as_str().unwrap().is_empty());
}
