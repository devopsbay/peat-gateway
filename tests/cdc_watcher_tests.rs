//! Integration tests for CDC change watcher.
//!
//! Uses peat-mesh's InMemoryBackend to simulate document changes and verifies
//! the full watcher → CDC engine → webhook delivery path.

#![cfg(feature = "webhook")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use peat_gateway::cdc::{CdcEngine, CdcWatcher};
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::models::{CdcEvent, CdcSinkType, EnrollmentPolicy};
use peat_gateway::tenant::TenantManager;
use peat_mesh::sync::in_memory::InMemoryBackend;
use peat_mesh::sync::traits::{DataSyncBackend, DocumentStore};
use peat_mesh::sync::types::{BackendConfig, Document, TransportConfig};
use serde_json::Value;
use tokio::sync::Mutex;

// ── Mock webhook receiver ──────────────────────────────────────

#[derive(Clone, Debug)]
struct CapturedRequest {
    body: Vec<u8>,
    change_hash: Option<String>,
    org_id_header: Option<String>,
}

#[derive(Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
    call_count: Arc<AtomicU32>,
}

impl MockState {
    fn new() -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            call_count: Arc::new(AtomicU32::new(0)),
        }
    }
}

async fn mock_handler(
    State(state): State<MockState>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    state.call_count.fetch_add(1, Ordering::SeqCst);
    state.requests.lock().await.push(CapturedRequest {
        body: body.to_vec(),
        change_hash: headers
            .get("x-peat-change-hash")
            .map(|v| v.to_str().unwrap().to_string()),
        org_id_header: headers
            .get("x-peat-org-id")
            .map(|v| v.to_str().unwrap().to_string()),
    });
    StatusCode::OK
}

async fn start_mock_webhook(state: MockState) -> (String, MockState) {
    let app = Router::new()
        .route("/hook", post(mock_handler))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/hook"), state)
}

// ── Helpers ────────────────────────────────────────────────────

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

async fn create_in_memory_backend(app_id: &str) -> (InMemoryBackend, Arc<dyn DocumentStore>) {
    let backend = InMemoryBackend::new();
    let config = BackendConfig {
        app_id: app_id.to_string(),
        persistence_dir: std::path::PathBuf::from("/tmp/peat-test"),
        shared_key: None,
        transport: TransportConfig::default(),
        extra: HashMap::new(),
    };
    backend.initialize(config).await.unwrap();
    let doc_store = backend.document_store();
    (backend, doc_store)
}

// ── Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn watcher_publishes_cdc_on_document_upsert() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    // Create org + formation + webhook sink
    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    // Set up watcher with InMemoryBackend
    let (_backend, doc_store) = create_in_memory_backend("logistics").await;
    let watcher = CdcWatcher::new(engine, tenant_mgr.clone());
    watcher
        .watch_formation("acme".into(), "logistics".into(), doc_store.clone())
        .await
        .unwrap();

    // Give watcher time to start observing
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Upsert a document — this should trigger a CDC event
    let mut fields = HashMap::new();
    fields.insert("status".to_string(), Value::String("shipped".to_string()));
    fields.insert("_actor".to_string(), Value::String("peer-42".to_string()));
    let doc = Document::with_id("order-001", fields);
    doc_store.upsert("acme.logistics", doc).await.unwrap();

    // Wait for watcher to process and webhook to deliver
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reqs = mock.requests.lock().await;
    assert_eq!(reqs.len(), 1, "Should have received one webhook delivery");

    let received: CdcEvent = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(received.org_id, "acme");
    assert_eq!(received.app_id, "logistics");
    assert_eq!(received.document_id, "order-001");
    assert_eq!(received.actor_id, "peer-42");
    assert_eq!(reqs[0].org_id_header.as_deref(), Some("acme"));
    assert!(reqs[0].change_hash.is_some());

    watcher.shutdown().await;
}

#[tokio::test]
async fn watcher_publishes_cdc_on_document_removal() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    let (_backend, doc_store) = create_in_memory_backend("logistics").await;
    let watcher = CdcWatcher::new(engine, tenant_mgr.clone());
    watcher
        .watch_formation("acme".into(), "logistics".into(), doc_store.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Insert then remove a document
    let doc = Document::with_id("order-002", HashMap::new());
    doc_store.upsert("acme.logistics", doc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    doc_store
        .remove("acme.logistics", &"order-002".to_string())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reqs = mock.requests.lock().await;
    assert!(reqs.len() >= 2, "Should have upsert + removal events");

    // Last event should be the removal
    let last: CdcEvent = serde_json::from_slice(&reqs.last().unwrap().body).unwrap();
    assert_eq!(last.document_id, "order-002");
    assert_eq!(last.patches, serde_json::json!({"_deleted": true}));

    watcher.shutdown().await;
}

#[tokio::test]
async fn watcher_multiple_documents_multiple_events() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("acme", "comms".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    let (_backend, doc_store) = create_in_memory_backend("comms").await;
    let watcher = CdcWatcher::new(engine, tenant_mgr.clone());
    watcher
        .watch_formation("acme".into(), "comms".into(), doc_store.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Upsert 3 documents
    for i in 0..3 {
        let mut fields = HashMap::new();
        fields.insert("seq".to_string(), Value::Number(i.into()));
        let doc = Document::with_id(format!("msg-{i}"), fields);
        doc_store.upsert("acme.comms", doc).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let reqs = mock.requests.lock().await;
    assert_eq!(reqs.len(), 3, "Should have 3 CDC events");

    // Verify all 3 document IDs
    let doc_ids: Vec<String> = reqs
        .iter()
        .map(|r| {
            let ev: CdcEvent = serde_json::from_slice(&r.body).unwrap();
            ev.document_id
        })
        .collect();
    assert!(doc_ids.contains(&"msg-0".to_string()));
    assert!(doc_ids.contains(&"msg-1".to_string()));
    assert!(doc_ids.contains(&"msg-2".to_string()));

    watcher.shutdown().await;
}

#[tokio::test]
async fn watcher_unwatch_stops_events() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    let (_backend, doc_store) = create_in_memory_backend("logistics").await;
    let watcher = CdcWatcher::new(engine, tenant_mgr.clone());
    watcher
        .watch_formation("acme".into(), "logistics".into(), doc_store.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // First upsert — should trigger CDC
    let doc = Document::with_id("order-a", HashMap::new());
    doc_store.upsert("acme.logistics", doc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let count_before = mock.call_count.load(Ordering::SeqCst);
    assert!(count_before >= 1);

    // Unwatch
    watcher.unwatch_formation("acme", "logistics").await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second upsert — should NOT trigger CDC
    let doc = Document::with_id("order-b", HashMap::new());
    doc_store.upsert("acme.logistics", doc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let count_after = mock.call_count.load(Ordering::SeqCst);
    assert_eq!(
        count_before, count_after,
        "No new events should fire after unwatch"
    );

    watcher.shutdown().await;
}

#[tokio::test]
async fn watcher_initial_snapshot_not_emitted() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    let (_backend, doc_store) = create_in_memory_backend("logistics").await;

    // Pre-populate documents BEFORE starting the watcher
    for i in 0..5 {
        let doc = Document::with_id(format!("existing-{i}"), HashMap::new());
        doc_store.upsert("acme.logistics", doc).await.unwrap();
    }

    let watcher = CdcWatcher::new(engine, tenant_mgr.clone());
    watcher
        .watch_formation("acme".into(), "logistics".into(), doc_store.clone())
        .await
        .unwrap();

    // Wait for initial snapshot to be processed
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reqs = mock.requests.lock().await;
    assert_eq!(
        reqs.len(),
        0,
        "Initial snapshot should NOT generate CDC events"
    );

    // Now upsert a new document — this SHOULD trigger
    drop(reqs);
    let doc = Document::with_id("new-doc", HashMap::new());
    doc_store.upsert("acme.logistics", doc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reqs = mock.requests.lock().await;
    assert_eq!(
        reqs.len(),
        1,
        "New document after observe should trigger CDC"
    );

    let received: CdcEvent = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(received.document_id, "new-doc");

    watcher.shutdown().await;
}

#[tokio::test]
async fn watcher_org_isolation() {
    let (tenant_mgr, engine, _dir) = setup().await;

    let mock_alpha = MockState::new();
    let (url_alpha, mock_alpha) = start_mock_webhook(mock_alpha).await;
    let mock_bravo = MockState::new();
    let (url_bravo, mock_bravo) = start_mock_webhook(mock_bravo).await;

    // Two orgs, each with a formation and webhook sink
    for (org, url) in [("alpha", url_alpha), ("bravo", url_bravo)] {
        tenant_mgr.create_org(org.into(), org.into()).await.unwrap();
        tenant_mgr
            .create_formation(org, "mesh".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
        tenant_mgr
            .create_sink(org, CdcSinkType::Webhook { url })
            .await
            .unwrap();
    }

    let (_be_alpha, store_alpha) = create_in_memory_backend("mesh").await;
    let (_be_bravo, store_bravo) = create_in_memory_backend("mesh").await;

    let watcher = CdcWatcher::new(engine, tenant_mgr.clone());
    watcher
        .watch_formation("alpha".into(), "mesh".into(), store_alpha.clone())
        .await
        .unwrap();
    watcher
        .watch_formation("bravo".into(), "mesh".into(), store_bravo.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Upsert in alpha's store only
    let doc = Document::with_id("alpha-doc", HashMap::new());
    store_alpha.upsert("alpha.mesh", doc).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let reqs_alpha = mock_alpha.requests.lock().await;
    let reqs_bravo = mock_bravo.requests.lock().await;

    assert_eq!(reqs_alpha.len(), 1, "Alpha should receive CDC event");
    assert_eq!(
        reqs_bravo.len(),
        0,
        "Bravo should NOT receive alpha's event"
    );

    watcher.shutdown().await;
}

#[tokio::test]
async fn watcher_cursor_deduplication() {
    let (tenant_mgr, engine, _dir) = setup().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    tenant_mgr
        .create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    let (_backend, doc_store) = create_in_memory_backend("logistics").await;

    // First watcher session: upsert a document, cursor gets persisted
    let watcher = CdcWatcher::new(engine.clone(), tenant_mgr.clone());
    watcher
        .watch_formation("acme".into(), "logistics".into(), doc_store.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    let mut fields = HashMap::new();
    fields.insert("status".to_string(), Value::String("ready".to_string()));
    let doc = Document::with_id("order-dedup", fields);
    doc_store.upsert("acme.logistics", doc).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        1,
        "First upsert should deliver"
    );

    // Verify cursor was persisted
    let cursor = tenant_mgr
        .get_cursor("acme", "logistics", "order-dedup")
        .await
        .unwrap();
    assert!(cursor.is_some(), "Cursor should be persisted after publish");

    // A different change to the same doc should still deliver (different hash)
    let mut fields2 = HashMap::new();
    fields2.insert("status".to_string(), Value::String("shipped".to_string()));
    let doc2 = Document::with_id("order-dedup", fields2);
    doc_store.upsert("acme.logistics", doc2).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        2,
        "Updated content should produce different hash and deliver"
    );

    // Verify cursor was updated to new hash
    let cursor2 = tenant_mgr
        .get_cursor("acme", "logistics", "order-dedup")
        .await
        .unwrap();
    assert!(cursor2.is_some());
    assert_ne!(
        cursor, cursor2,
        "Cursor should update after new change is published"
    );

    watcher.shutdown().await;
}
