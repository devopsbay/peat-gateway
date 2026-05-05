//! Integration tests for webhook CDC sink delivery.
//!
//! Uses an in-process axum server as the mock webhook receiver to test:
//! - Successful delivery with correct payload + headers
//! - Retry on 5xx with eventual success
//! - Immediate failure on 4xx (no retry)
//! - All retries exhausted on persistent server error
//! - Disabled sink suppression
//! - Multi-sink fan-out to multiple webhooks
//! - Org isolation (no cross-delivery)

#![cfg(feature = "webhook")]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use peat_gateway::cdc::CdcEngine;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::models::{CdcEvent, CdcSinkType, EnrollmentPolicy};
use peat_gateway::tenant::TenantManager;
use serde_json::json;
use tokio::sync::Mutex;

// ── Helpers ────────────────────────────────────────────────────

fn sample_event(org_id: &str, app_id: &str) -> CdcEvent {
    CdcEvent {
        org_id: org_id.into(),
        app_id: app_id.into(),
        document_id: "doc-001".into(),
        change_hash: "webhash-abc123".into(),
        actor_id: "peer-42".into(),
        timestamp_ms: 1700000000000,
        patches: json!([{"op": "add", "path": "/key", "value": "hello"}]),
    }
}

async fn setup() -> (TenantManager, CdcEngine, tempfile::TempDir) {
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
    let engine = CdcEngine::new(&config, tenant_mgr.clone()).await.unwrap();
    (tenant_mgr, engine, dir)
}

/// Captured webhook request.
#[derive(Clone, Debug)]
struct CapturedRequest {
    body: Vec<u8>,
    content_type: Option<String>,
    change_hash: Option<String>,
    org_id_header: Option<String>,
}

/// Shared state for the mock webhook server.
#[derive(Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    call_count: Arc<AtomicU32>,
    /// Status code to return. Can be changed between calls.
    response_status: Arc<Mutex<StatusCode>>,
    /// If set, fail the first N requests with 500 then succeed.
    fail_first_n: Arc<AtomicU32>,
}

impl MockState {
    fn new(status: StatusCode) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            call_count: Arc::new(AtomicU32::new(0)),
            response_status: Arc::new(Mutex::new(status)),
            fail_first_n: Arc::new(AtomicU32::new(0)),
        }
    }

    fn with_fail_first(mut self, n: u32) -> Self {
        self.fail_first_n = Arc::new(AtomicU32::new(n));
        self
    }
}

async fn mock_webhook_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let count = state.call_count.fetch_add(1, Ordering::SeqCst);

    state.requests.lock().await.push(CapturedRequest {
        body: body.to_vec(),
        content_type: headers
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_string()),
        change_hash: headers
            .get("x-peat-change-hash")
            .map(|v| v.to_str().unwrap().to_string()),
        org_id_header: headers
            .get("x-peat-org-id")
            .map(|v| v.to_str().unwrap().to_string()),
    });

    let fail_n = state.fail_first_n.load(Ordering::SeqCst);
    if fail_n > 0 && count < fail_n {
        return StatusCode::INTERNAL_SERVER_ERROR;
    }

    *state.response_status.lock().await
}

/// Start a mock webhook server, returning its URL and shared state.
async fn start_mock_webhook(state: MockState) -> (String, MockState) {
    let app = Router::new()
        .route("/hook", post(mock_webhook_handler))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}/hook"), state)
}

/// Helper: create org + formation + webhook sink, returns the webhook URL.
async fn setup_org_with_webhook(
    tenant_mgr: &TenantManager,
    org_id: &str,
    app_id: &str,
    webhook_url: &str,
) {
    tenant_mgr
        .create_org(org_id.into(), format!("{org_id} Corp"))
        .await
        .unwrap();
    tenant_mgr
        .create_formation(org_id, app_id.into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink(
            org_id,
            CdcSinkType::Webhook {
                url: webhook_url.into(),
            },
        )
        .await
        .unwrap();
}

// ── Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn webhook_delivers_event_with_correct_payload_and_headers() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let state = MockState::new(StatusCode::OK);
    let (url, state) = start_mock_webhook(state).await;

    setup_org_with_webhook(&tenant_mgr, "acme", "logistics", &url).await;

    let event = sample_event("acme", "logistics");
    engine.publish(&event).await.unwrap();

    let reqs = state.requests.lock().await;
    assert_eq!(reqs.len(), 1);

    let req = &reqs[0];
    assert_eq!(req.content_type.as_deref(), Some("application/json"));
    assert_eq!(req.change_hash.as_deref(), Some("webhash-abc123"));
    assert_eq!(req.org_id_header.as_deref(), Some("acme"));

    let received: CdcEvent = serde_json::from_slice(&req.body).unwrap();
    assert_eq!(received.org_id, "acme");
    assert_eq!(received.app_id, "logistics");
    assert_eq!(received.document_id, "doc-001");
    assert_eq!(received.change_hash, "webhash-abc123");
    assert_eq!(received.actor_id, "peer-42");
    assert_eq!(received.timestamp_ms, 1700000000000);
}

#[tokio::test]
async fn webhook_retries_on_5xx_then_succeeds() {
    let (tenant_mgr, engine, _dir) = setup().await;
    // Fail first 2 requests with 500, then succeed
    let state = MockState::new(StatusCode::OK).with_fail_first(2);
    let (url, state) = start_mock_webhook(state).await;

    setup_org_with_webhook(&tenant_mgr, "acme", "logistics", &url).await;

    let event = sample_event("acme", "logistics");
    engine.publish(&event).await.unwrap();

    let reqs = state.requests.lock().await;
    // Should have made 3 requests: 2 failures + 1 success
    assert_eq!(reqs.len(), 3);
    assert_eq!(state.call_count.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn webhook_fails_immediately_on_4xx() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let state = MockState::new(StatusCode::BAD_REQUEST);
    let (url, state) = start_mock_webhook(state).await;

    setup_org_with_webhook(&tenant_mgr, "acme", "logistics", &url).await;

    let event = sample_event("acme", "logistics");
    // CdcEngine logs warnings but doesn't propagate errors — it continues to other sinks.
    // The webhook sink itself returns Err, but engine swallows it.
    engine.publish(&event).await.unwrap();

    let reqs = state.requests.lock().await;
    // Should have made exactly 1 request (no retries on 4xx)
    assert_eq!(reqs.len(), 1);
    assert_eq!(state.call_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn webhook_exhausts_retries_on_persistent_5xx() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let state = MockState::new(StatusCode::INTERNAL_SERVER_ERROR);
    let (url, state) = start_mock_webhook(state).await;

    setup_org_with_webhook(&tenant_mgr, "acme", "logistics", &url).await;

    let event = sample_event("acme", "logistics");
    let start = Instant::now();
    engine.publish(&event).await.unwrap();
    let elapsed = start.elapsed();

    // MAX_RETRIES=3, so 4 total attempts (initial + 3 retries)
    assert_eq!(state.call_count.load(Ordering::SeqCst), 4);

    // Backoff: 100ms + 200ms + 400ms = 700ms minimum
    assert!(
        elapsed.as_millis() >= 500,
        "Expected at least 500ms of backoff, got {}ms",
        elapsed.as_millis()
    );
}

#[tokio::test]
async fn webhook_disabled_sink_does_not_deliver() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let state = MockState::new(StatusCode::OK);
    let (url, state) = start_mock_webhook(state).await;

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    let sink = tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url: url.clone() })
        .await
        .unwrap();

    // Disable the sink
    tenant_mgr
        .toggle_sink("acme", &sink.sink_id, false)
        .await
        .unwrap();

    let event = sample_event("acme", "logistics");
    engine.publish(&event).await.unwrap();

    let reqs = state.requests.lock().await;
    assert_eq!(reqs.len(), 0, "Disabled sink should not deliver");
}

#[tokio::test]
async fn webhook_fan_out_to_multiple_sinks() {
    let (tenant_mgr, engine, _dir) = setup().await;

    let state_a = MockState::new(StatusCode::OK);
    let (url_a, state_a) = start_mock_webhook(state_a).await;
    let state_b = MockState::new(StatusCode::OK);
    let (url_b, state_b) = start_mock_webhook(state_b).await;

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("acme", "comms".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url: url_a })
        .await
        .unwrap();
    tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url: url_b })
        .await
        .unwrap();

    let event = CdcEvent {
        org_id: "acme".into(),
        app_id: "comms".into(),
        document_id: "doc-fanout".into(),
        change_hash: "hash-fanout".into(),
        actor_id: "peer-1".into(),
        timestamp_ms: 1700000000000,
        patches: json!({"changed": true}),
    };
    engine.publish(&event).await.unwrap();

    let reqs_a = state_a.requests.lock().await;
    let reqs_b = state_b.requests.lock().await;
    assert_eq!(reqs_a.len(), 1, "Webhook A should receive event");
    assert_eq!(reqs_b.len(), 1, "Webhook B should receive event");

    let ev_a: CdcEvent = serde_json::from_slice(&reqs_a[0].body).unwrap();
    let ev_b: CdcEvent = serde_json::from_slice(&reqs_b[0].body).unwrap();
    assert_eq!(ev_a.document_id, "doc-fanout");
    assert_eq!(ev_b.document_id, "doc-fanout");
}

#[tokio::test]
async fn webhook_org_isolation_no_cross_delivery() {
    let (tenant_mgr, engine, _dir) = setup().await;

    let state_alpha = MockState::new(StatusCode::OK);
    let (url_alpha, state_alpha) = start_mock_webhook(state_alpha).await;
    let state_bravo = MockState::new(StatusCode::OK);
    let (url_bravo, state_bravo) = start_mock_webhook(state_bravo).await;

    setup_org_with_webhook(&tenant_mgr, "alpha", "mesh", &url_alpha).await;
    setup_org_with_webhook(&tenant_mgr, "bravo", "mesh", &url_bravo).await;

    // Publish event for alpha only
    let event = CdcEvent {
        org_id: "alpha".into(),
        app_id: "mesh".into(),
        document_id: "doc-iso".into(),
        change_hash: "hash-iso".into(),
        actor_id: "peer-a".into(),
        timestamp_ms: 1700000000000,
        patches: json!(null),
    };
    engine.publish(&event).await.unwrap();

    let reqs_alpha = state_alpha.requests.lock().await;
    let reqs_bravo = state_bravo.requests.lock().await;

    assert_eq!(reqs_alpha.len(), 1, "Alpha should receive event");
    assert_eq!(
        reqs_bravo.len(),
        0,
        "Bravo should NOT receive alpha's event"
    );

    let received: CdcEvent = serde_json::from_slice(&reqs_alpha[0].body).unwrap();
    assert_eq!(received.org_id, "alpha");
}

#[tokio::test]
async fn webhook_unreachable_endpoint_exhausts_retries() {
    let (tenant_mgr, engine, _dir) = setup().await;

    // Point to a port that nothing is listening on
    let url = "http://127.0.0.1:1/hook".to_string();

    setup_org_with_webhook(&tenant_mgr, "acme", "logistics", &url).await;

    let event = sample_event("acme", "logistics");
    let start = Instant::now();
    // Engine swallows the error
    engine.publish(&event).await.unwrap();
    let elapsed = start.elapsed();

    // Should have attempted retries with backoff.
    // We can't check call_count (no server), but we can verify
    // it took time due to backoff + timeouts
    assert!(
        elapsed.as_millis() >= 200,
        "Expected backoff delay, got {}ms",
        elapsed.as_millis()
    );
}
