//! Error recovery tests: CDC watcher resilience with failing storage.
//!
//! Uses a `FailingStorage` wrapper that can inject failures into cursor operations
//! to verify the watcher continues processing events after internal errors.

#![cfg(feature = "webhook")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::Router;
use peat_gateway::cdc::{CdcEngine, CdcWatcher};
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::crypto;
use peat_gateway::storage::{self, StorageBackend};
use peat_gateway::tenant::models::*;
use peat_gateway::tenant::TenantManager;
use peat_mesh::sync::in_memory::InMemoryBackend;
use peat_mesh::sync::traits::{DataSyncBackend, DocumentStore};
use peat_mesh::sync::types::{BackendConfig, Document, TransportConfig};
use serde_json::Value;
use tokio::sync::Mutex;

// ── FailingStorage wrapper ──────────────────────────────────────

/// Wraps a real StorageBackend but can inject failures on cursor operations.
struct FailingStorage {
    inner: Box<dyn StorageBackend>,
    fail_set_cursor: AtomicBool,
    fail_get_cursor: AtomicBool,
}

impl FailingStorage {
    fn new(inner: Box<dyn StorageBackend>) -> Self {
        Self {
            inner,
            fail_set_cursor: AtomicBool::new(false),
            fail_get_cursor: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl StorageBackend for FailingStorage {
    // --- Cursor operations (can fail) ---

    async fn get_cursor(
        &self,
        org_id: &str,
        app_id: &str,
        document_id: &str,
    ) -> Result<Option<String>> {
        if self.fail_get_cursor.load(Ordering::SeqCst) {
            anyhow::bail!("injected get_cursor failure");
        }
        self.inner.get_cursor(org_id, app_id, document_id).await
    }

    async fn set_cursor(
        &self,
        org_id: &str,
        app_id: &str,
        document_id: &str,
        change_hash: &str,
    ) -> Result<()> {
        if self.fail_set_cursor.load(Ordering::SeqCst) {
            anyhow::bail!("injected set_cursor failure");
        }
        self.inner
            .set_cursor(org_id, app_id, document_id, change_hash)
            .await
    }

    // --- All other methods delegate unchanged ---

    async fn create_org(&self, org: &Organization) -> Result<()> {
        self.inner.create_org(org).await
    }
    async fn get_org(&self, org_id: &str) -> Result<Option<Organization>> {
        self.inner.get_org(org_id).await
    }
    async fn list_orgs(&self) -> Result<Vec<Organization>> {
        self.inner.list_orgs().await
    }
    async fn update_org(&self, org: &Organization) -> Result<()> {
        self.inner.update_org(org).await
    }
    async fn delete_org(&self, org_id: &str) -> Result<bool> {
        self.inner.delete_org(org_id).await
    }

    async fn create_formation(&self, org_id: &str, formation: &FormationConfig) -> Result<()> {
        self.inner.create_formation(org_id, formation).await
    }
    async fn get_formation(&self, org_id: &str, app_id: &str) -> Result<Option<FormationConfig>> {
        self.inner.get_formation(org_id, app_id).await
    }
    async fn list_formations(&self, org_id: &str) -> Result<Vec<FormationConfig>> {
        self.inner.list_formations(org_id).await
    }
    async fn delete_formation(&self, org_id: &str, app_id: &str) -> Result<bool> {
        self.inner.delete_formation(org_id, app_id).await
    }

    async fn create_token(&self, token: &EnrollmentToken) -> Result<()> {
        self.inner.create_token(token).await
    }
    async fn get_token(&self, org_id: &str, token_id: &str) -> Result<Option<EnrollmentToken>> {
        self.inner.get_token(org_id, token_id).await
    }
    async fn list_tokens(&self, org_id: &str, app_id: &str) -> Result<Vec<EnrollmentToken>> {
        self.inner.list_tokens(org_id, app_id).await
    }
    async fn update_token(&self, token: &EnrollmentToken) -> Result<()> {
        self.inner.update_token(token).await
    }
    async fn delete_token(&self, org_id: &str, token_id: &str) -> Result<bool> {
        self.inner.delete_token(org_id, token_id).await
    }

    async fn create_sink(&self, sink: &CdcSinkConfig) -> Result<()> {
        self.inner.create_sink(sink).await
    }
    async fn get_sink(&self, org_id: &str, sink_id: &str) -> Result<Option<CdcSinkConfig>> {
        self.inner.get_sink(org_id, sink_id).await
    }
    async fn list_sinks(&self, org_id: &str) -> Result<Vec<CdcSinkConfig>> {
        self.inner.list_sinks(org_id).await
    }
    async fn update_sink(&self, sink: &CdcSinkConfig) -> Result<()> {
        self.inner.update_sink(sink).await
    }
    async fn delete_sink(&self, org_id: &str, sink_id: &str) -> Result<bool> {
        self.inner.delete_sink(org_id, sink_id).await
    }

    async fn create_idp(&self, idp: &IdpConfig) -> Result<()> {
        self.inner.create_idp(idp).await
    }
    async fn get_idp(&self, org_id: &str, idp_id: &str) -> Result<Option<IdpConfig>> {
        self.inner.get_idp(org_id, idp_id).await
    }
    async fn list_idps(&self, org_id: &str) -> Result<Vec<IdpConfig>> {
        self.inner.list_idps(org_id).await
    }
    async fn update_idp(&self, idp: &IdpConfig) -> Result<()> {
        self.inner.update_idp(idp).await
    }
    async fn delete_idp(&self, org_id: &str, idp_id: &str) -> Result<bool> {
        self.inner.delete_idp(org_id, idp_id).await
    }

    async fn create_policy_rule(&self, rule: &PolicyRule) -> Result<()> {
        self.inner.create_policy_rule(rule).await
    }
    async fn list_policy_rules(&self, org_id: &str) -> Result<Vec<PolicyRule>> {
        self.inner.list_policy_rules(org_id).await
    }
    async fn delete_policy_rule(&self, org_id: &str, rule_id: &str) -> Result<bool> {
        self.inner.delete_policy_rule(org_id, rule_id).await
    }

    async fn append_audit(&self, entry: &EnrollmentAuditEntry) -> Result<()> {
        self.inner.append_audit(entry).await
    }
    async fn list_audit(
        &self,
        org_id: &str,
        app_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<EnrollmentAuditEntry>> {
        self.inner.list_audit(org_id, app_id, limit).await
    }

    async fn store_genesis(&self, org_id: &str, app_id: &str, encoded: &[u8]) -> Result<()> {
        self.inner.store_genesis(org_id, app_id, encoded).await
    }
    async fn get_genesis(&self, org_id: &str, app_id: &str) -> Result<Option<Vec<u8>>> {
        self.inner.get_genesis(org_id, app_id).await
    }
    async fn delete_genesis(&self, org_id: &str, app_id: &str) -> Result<bool> {
        self.inner.delete_genesis(org_id, app_id).await
    }
}

// ── Mock webhook receiver ───────────────────────────────────────

#[derive(Clone)]
struct MockState {
    requests: Arc<Mutex<Vec<Vec<u8>>>>,
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
    _headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    state.call_count.fetch_add(1, Ordering::SeqCst);
    state.requests.lock().await.push(body.to_vec());
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

// ── Helpers ─────────────────────────────────────────────────────

async fn setup_failing() -> (
    Arc<FailingStorage>,
    TenantManager,
    CdcEngine,
    tempfile::TempDir,
) {
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

    let inner = storage::open(&config.storage).await.unwrap();
    let failing = Arc::new(FailingStorage::new(inner));
    let (key_provider, encrypt_enabled) = crypto::build_key_provider(&config).await.unwrap();

    let mgr = TenantManager::with_backend(failing.clone(), key_provider, encrypt_enabled);
    let engine = CdcEngine::new(&config, mgr.clone()).await.unwrap();

    (failing, mgr, engine, dir)
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

// ── Tests ───────────────────────────────────────────────────────

/// When set_cursor fails, the event should still be delivered to the webhook
/// and the watcher should continue processing subsequent events.
#[tokio::test]
async fn watcher_continues_after_cursor_write_failure() {
    let (failing, mgr, engine, _dir) = setup_failing().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    mgr.create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    // Enable cursor write failures
    failing.fail_set_cursor.store(true, Ordering::SeqCst);

    let (_backend, doc_store) = create_in_memory_backend("logistics").await;
    let watcher = CdcWatcher::new(engine, mgr.clone());
    watcher
        .watch_formation("acme".into(), "logistics".into(), doc_store.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Upsert two documents — both should be delivered despite cursor failures
    let doc1 = Document::with_id("order-1", HashMap::new());
    doc_store.upsert("acme.logistics", doc1).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let doc2 = Document::with_id("order-2", HashMap::new());
    doc_store.upsert("acme.logistics", doc2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    let count = mock.call_count.load(Ordering::SeqCst);
    assert_eq!(
        count, 2,
        "Both events should be delivered despite cursor write failures"
    );

    // Verify cursor was NOT persisted (because set_cursor is failing)
    failing.fail_set_cursor.store(false, Ordering::SeqCst);
    let cursor = mgr
        .get_cursor("acme", "logistics", "order-1")
        .await
        .unwrap();
    assert!(
        cursor.is_none(),
        "Cursor should not be persisted when set_cursor fails"
    );

    watcher.shutdown().await;
}

/// When get_cursor fails, deduplication is skipped but the event is still
/// processed and delivered normally.
#[tokio::test]
async fn watcher_delivers_without_dedup_on_cursor_read_failure() {
    let (failing, mgr, engine, _dir) = setup_failing().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    mgr.create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    // Enable cursor read failures
    failing.fail_get_cursor.store(true, Ordering::SeqCst);

    let (_backend, doc_store) = create_in_memory_backend("logistics").await;
    let watcher = CdcWatcher::new(engine, mgr.clone());
    watcher
        .watch_formation("acme".into(), "logistics".into(), doc_store.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Upsert a document — should still be delivered (dedup skipped)
    let mut fields = HashMap::new();
    fields.insert("status".to_string(), Value::String("ready".to_string()));
    let doc = Document::with_id("order-dedup", fields);
    doc_store.upsert("acme.logistics", doc).await.unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        1,
        "Event should be delivered even when get_cursor fails"
    );

    // Cursor should still be persisted (set_cursor is working)
    let cursor = mgr.get_cursor("acme", "logistics", "order-dedup").await;
    // get_cursor is still failing, so this will error
    assert!(
        cursor.is_err(),
        "get_cursor should still be failing for the test"
    );

    // Disable failure and verify cursor was actually persisted
    failing.fail_get_cursor.store(false, Ordering::SeqCst);
    let cursor = mgr
        .get_cursor("acme", "logistics", "order-dedup")
        .await
        .unwrap();
    assert!(
        cursor.is_some(),
        "Cursor should be persisted even when get_cursor was failing"
    );

    watcher.shutdown().await;
}

/// When cursor write fails temporarily, the watcher recovers and persists
/// cursors once the failure clears.
#[tokio::test]
async fn watcher_recovers_cursor_persistence_after_transient_failure() {
    let (failing, mgr, engine, _dir) = setup_failing().await;
    let mock = MockState::new();
    let (url, mock) = start_mock_webhook(mock).await;

    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "logistics".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    mgr.create_sink("acme", CdcSinkType::Webhook { url })
        .await
        .unwrap();

    let (_backend, doc_store) = create_in_memory_backend("logistics").await;
    let watcher = CdcWatcher::new(engine, mgr.clone());
    watcher
        .watch_formation("acme".into(), "logistics".into(), doc_store.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Phase 1: cursor write fails
    failing.fail_set_cursor.store(true, Ordering::SeqCst);
    let doc1 = Document::with_id("order-transient", HashMap::new());
    doc_store.upsert("acme.logistics", doc1).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        1,
        "Event delivered during failure"
    );

    // Phase 2: cursor write recovers
    failing.fail_set_cursor.store(false, Ordering::SeqCst);
    let mut fields = HashMap::new();
    fields.insert("status".to_string(), Value::String("updated".to_string()));
    let doc2 = Document::with_id("order-recovered", fields);
    doc_store.upsert("acme.logistics", doc2).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert_eq!(
        mock.call_count.load(Ordering::SeqCst),
        2,
        "Event delivered after recovery"
    );

    // Cursor should now be persisted for the second event
    let cursor = mgr
        .get_cursor("acme", "logistics", "order-recovered")
        .await
        .unwrap();
    assert!(
        cursor.is_some(),
        "Cursor should be persisted after failure clears"
    );

    // Cursor should NOT be persisted for the first event (it failed)
    let cursor = mgr
        .get_cursor("acme", "logistics", "order-transient")
        .await
        .unwrap();
    assert!(
        cursor.is_none(),
        "Cursor from failure period should not be persisted"
    );

    watcher.shutdown().await;
}
