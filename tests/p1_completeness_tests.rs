//! P1 completeness tests for single-node production readiness.
//!
//! Covers: Kafka sink lifecycle (#32), numeric edge cases (#33),
//! token re-creation after deletion (#34), quota boundary conditions (#36).

use std::net::SocketAddr;

use peat_gateway::api;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};

use peat_gateway::tenant::TenantManager;
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};

// ── Helpers ──────────────────────────────────────────────────────

async fn spawn_app() -> (Client, String, TenantManager, tempfile::TempDir) {
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

async fn create_org(client: &Client, base: &str, org_id: &str) {
    client
        .post(format!("{base}/orgs"))
        .json(&json!({"org_id": org_id, "display_name": format!("{org_id} Corp")}))
        .send()
        .await
        .unwrap();
}

async fn set_quotas(client: &Client, base: &str, org_id: &str, quotas: Value) {
    client
        .patch(format!("{base}/orgs/{org_id}"))
        .json(&json!({"quotas": quotas}))
        .send()
        .await
        .unwrap();
}

// ═══════════════════════════════════════════════════════════════════
// #32 — Kafka sink type lifecycle
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn kafka_sink_create_list_toggle_delete() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "kafka-org").await;

    // Create Kafka sink
    let resp = client
        .post(format!("{base}/orgs/kafka-org/sinks"))
        .json(&json!({"sink_type": {"Kafka": {"topic": "cdc-events"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let sink: Value = resp.json().await.unwrap();
    let sink_id = sink["sink_id"].as_str().unwrap().to_string();
    assert_eq!(sink["sink_type"]["Kafka"]["topic"], "cdc-events");
    assert_eq!(sink["enabled"], true);

    // List — should include our Kafka sink
    let resp = client
        .get(format!("{base}/orgs/kafka-org/sinks"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let sinks: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(sinks.len(), 1);
    assert!(sinks[0]["sink_type"]["Kafka"].is_object());

    // Toggle disabled
    let resp = client
        .patch(format!("{base}/orgs/kafka-org/sinks/{sink_id}"))
        .json(&json!({"enabled": false}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let toggled: Value = resp.json().await.unwrap();
    assert_eq!(toggled["enabled"], false);

    // Toggle re-enabled
    let resp = client
        .patch(format!("{base}/orgs/kafka-org/sinks/{sink_id}"))
        .json(&json!({"enabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let toggled: Value = resp.json().await.unwrap();
    assert_eq!(toggled["enabled"], true);

    // Delete
    let resp = client
        .delete(format!("{base}/orgs/kafka-org/sinks/{sink_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify gone
    let resp = client
        .get(format!("{base}/orgs/kafka-org/sinks/{sink_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn kafka_sink_empty_topic_rejected() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "kafka-val").await;

    let resp = client
        .post(format!("{base}/orgs/kafka-val/sinks"))
        .json(&json!({"sink_type": {"Kafka": {"topic": ""}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ═══════════════════════════════════════════════════════════════════
// #33 — Numeric edge cases for quotas and limits
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn zero_formation_quota_blocks_creation() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "zero-org").await;

    set_quotas(
        &client,
        &base,
        "zero-org",
        json!({"max_formations": 0, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 5, "max_enrollments_per_hour": 1000}),
    )
    .await;

    let resp = client
        .post(format!("{base}/orgs/zero-org/formations"))
        .json(&json!({"app_id": "should-fail"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "zero quota should block formation creation"
    );
}

#[tokio::test]
async fn zero_sink_quota_blocks_creation() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "zero-sink").await;

    set_quotas(
        &client,
        &base,
        "zero-sink",
        json!({"max_formations": 10, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 0, "max_enrollments_per_hour": 1000}),
    )
    .await;

    let resp = client
        .post(format!("{base}/orgs/zero-sink/sinks"))
        .json(&json!({"sink_type": {"Nats": {"subject_prefix": "test"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "zero sink quota should block creation"
    );
}

#[tokio::test]
async fn exact_formation_quota_allows_then_blocks() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "exact-org").await;

    // Set quota to exactly 2
    set_quotas(
        &client,
        &base,
        "exact-org",
        json!({"max_formations": 2, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 5, "max_enrollments_per_hour": 1000}),
    )
    .await;

    // First two should succeed
    for i in 0..2 {
        let resp = client
            .post(format!("{base}/orgs/exact-org/formations"))
            .json(&json!({"app_id": format!("app-{i}")}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "formation {i} should succeed"
        );
    }

    // Third should fail
    let resp = client
        .post(format!("{base}/orgs/exact-org/formations"))
        .json(&json!({"app_id": "app-over"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "over-quota formation should be rejected"
    );
}

#[tokio::test]
async fn exact_sink_quota_allows_then_blocks() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "exact-sink").await;

    set_quotas(
        &client,
        &base,
        "exact-sink",
        json!({"max_formations": 10, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 2, "max_enrollments_per_hour": 1000}),
    )
    .await;

    for i in 0..2 {
        let resp = client
            .post(format!("{base}/orgs/exact-sink/sinks"))
            .json(&json!({"sink_type": {"Nats": {"subject_prefix": format!("prefix-{i}")}}}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "sink {i} should succeed"
        );
    }

    let resp = client
        .post(format!("{base}/orgs/exact-sink/sinks"))
        .json(&json!({"sink_type": {"Nats": {"subject_prefix": "over"}}}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "over-quota sink should be rejected"
    );
}

#[tokio::test]
async fn large_quota_values_do_not_overflow() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "big-org").await;

    // Set quotas to u32::MAX
    let resp = client
        .patch(format!("{base}/orgs/big-org"))
        .json(&json!({
            "quotas": {
                "max_formations": u32::MAX,
                "max_peers_per_formation": u32::MAX,
                "max_documents_per_formation": u32::MAX,
                "max_cdc_sinks": u32::MAX,
                "max_enrollments_per_hour": u32::MAX
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let org: Value = resp.json().await.unwrap();
    assert_eq!(org["quotas"]["max_formations"], u32::MAX);

    // Should be able to create a formation
    let resp = client
        .post(format!("{base}/orgs/big-org/formations"))
        .json(&json!({"app_id": "big-app"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// ═══════════════════════════════════════════════════════════════════
// #34 — Token re-creation after deletion
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn token_delete_and_recreate_with_same_label() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "tok-org").await;

    // Create formation for tokens
    client
        .post(format!("{base}/orgs/tok-org/formations"))
        .json(&json!({"app_id": "tok-mesh", "enrollment_policy": "Open"}))
        .send()
        .await
        .unwrap();

    // Create first token
    let resp = client
        .post(format!("{base}/orgs/tok-org/tokens"))
        .json(&json!({"app_id": "tok-mesh", "label": "device-token"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token1: Value = resp.json().await.unwrap();
    let token1_id = token1["token_id"].as_str().unwrap().to_string();

    // Delete it
    let resp = client
        .delete(format!("{base}/orgs/tok-org/tokens/{token1_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify deleted
    let resp = client
        .get(format!("{base}/orgs/tok-org/tokens/{token1_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // Create new token with same label
    let resp = client
        .post(format!("{base}/orgs/tok-org/tokens"))
        .json(&json!({"app_id": "tok-mesh", "label": "device-token"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let token2: Value = resp.json().await.unwrap();
    let token2_id = token2["token_id"].as_str().unwrap().to_string();

    // New token should have a different ID
    assert_ne!(token1_id, token2_id, "new token should have a fresh ID");

    // New token should be retrievable
    let resp = client
        .get(format!("{base}/orgs/tok-org/tokens/{token2_id}"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn revoked_token_still_visible_in_list() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "rev-org").await;

    client
        .post(format!("{base}/orgs/rev-org/formations"))
        .json(&json!({"app_id": "rev-mesh", "enrollment_policy": "Open"}))
        .send()
        .await
        .unwrap();

    let resp = client
        .post(format!("{base}/orgs/rev-org/tokens"))
        .json(&json!({"app_id": "rev-mesh", "label": "temp-token"}))
        .send()
        .await
        .unwrap();
    let token: Value = resp.json().await.unwrap();
    let token_id = token["token_id"].as_str().unwrap().to_string();

    // Revoke
    let resp = client
        .post(format!("{base}/orgs/rev-org/tokens/{token_id}/revoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let revoked: Value = resp.json().await.unwrap();
    assert_eq!(revoked["revoked"], true);

    // Should still appear in list
    let resp = client
        .get(format!("{base}/orgs/rev-org/formations/rev-mesh/tokens"))
        .send()
        .await
        .unwrap();
    let tokens: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(tokens[0]["revoked"], true);

    // Double-revoke should fail
    let resp = client
        .post(format!("{base}/orgs/rev-org/tokens/{token_id}/revoke"))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "double revoke should fail"
    );
}

// ═══════════════════════════════════════════════════════════════════
// #36 — Quota boundary conditions
// ═══════════════════════════════════════════════════════════════════

#[tokio::test]
async fn quota_increase_allows_new_creates() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "grow-org").await;

    // Quota of 1
    set_quotas(
        &client,
        &base,
        "grow-org",
        json!({"max_formations": 1, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 5, "max_enrollments_per_hour": 1000}),
    )
    .await;

    // First succeeds
    let resp = client
        .post(format!("{base}/orgs/grow-org/formations"))
        .json(&json!({"app_id": "first"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Second blocked
    let resp = client
        .post(format!("{base}/orgs/grow-org/formations"))
        .json(&json!({"app_id": "second"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Increase quota to 5
    set_quotas(
        &client,
        &base,
        "grow-org",
        json!({"max_formations": 5, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 5, "max_enrollments_per_hour": 1000}),
    )
    .await;

    // Now second succeeds
    let resp = client
        .post(format!("{base}/orgs/grow-org/formations"))
        .json(&json!({"app_id": "second"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn quota_decrease_preserves_existing_resources() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "shrink-org").await;

    // Start with quota of 5
    set_quotas(
        &client,
        &base,
        "shrink-org",
        json!({"max_formations": 5, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 5, "max_enrollments_per_hour": 1000}),
    )
    .await;

    // Create 3 formations
    for i in 0..3 {
        client
            .post(format!("{base}/orgs/shrink-org/formations"))
            .json(&json!({"app_id": format!("app-{i}")}))
            .send()
            .await
            .unwrap();
    }

    // Decrease quota to 2 (below current count of 3)
    set_quotas(
        &client,
        &base,
        "shrink-org",
        json!({"max_formations": 2, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 5, "max_enrollments_per_hour": 1000}),
    )
    .await;

    // Existing formations should still be visible
    let resp = client
        .get(format!("{base}/orgs/shrink-org/formations"))
        .send()
        .await
        .unwrap();
    let formations: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(
        formations.len(),
        3,
        "existing formations should be preserved"
    );

    // But new creation should be blocked
    let resp = client
        .post(format!("{base}/orgs/shrink-org/formations"))
        .json(&json!({"app_id": "app-blocked"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "new creation should be blocked when over reduced quota"
    );
}

#[tokio::test]
async fn delete_below_quota_allows_creation_again() {
    let (client, base, _mgr, _dir) = spawn_app().await;
    create_org(&client, &base, "recycle-org").await;

    set_quotas(
        &client,
        &base,
        "recycle-org",
        json!({"max_formations": 2, "max_peers_per_formation": 100, "max_documents_per_formation": 10000, "max_cdc_sinks": 5, "max_enrollments_per_hour": 1000}),
    )
    .await;

    // Fill quota
    for i in 0..2 {
        client
            .post(format!("{base}/orgs/recycle-org/formations"))
            .json(&json!({"app_id": format!("app-{i}")}))
            .send()
            .await
            .unwrap();
    }

    // Blocked
    let resp = client
        .post(format!("{base}/orgs/recycle-org/formations"))
        .json(&json!({"app_id": "app-blocked"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Delete one
    client
        .delete(format!("{base}/orgs/recycle-org/formations/app-0"))
        .send()
        .await
        .unwrap();

    // Now creation works again
    let resp = client
        .post(format!("{base}/orgs/recycle-org/formations"))
        .json(&json!({"app_id": "app-replacement"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
}
