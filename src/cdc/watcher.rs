use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;

use anyhow::{Context, Result};
use peat_mesh::sync::traits::DocumentStore;
use peat_mesh::sync::types::{ChangeEvent, Query};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::tenant::models::CdcEvent;
use crate::tenant::TenantManager;

use super::CdcEngine;

/// Key for a formation watcher: (org_id, app_id)
type FormationKey = (String, String);

/// Watches peat-mesh document stores for changes and publishes CDC events.
///
/// Each formation gets its own background task that calls `DocumentStore::observe()`
/// and converts `ChangeEvent` into `CdcEvent` for the CDC engine.
///
/// Persists a cursor (last emitted change_hash) per document so that duplicate
/// events are suppressed on restart.
pub struct CdcWatcher {
    engine: CdcEngine,
    tenant_mgr: TenantManager,
    handles: Arc<Mutex<HashMap<FormationKey, JoinHandle<()>>>>,
}

impl CdcWatcher {
    pub fn new(engine: CdcEngine, tenant_mgr: TenantManager) -> Self {
        Self {
            engine,
            tenant_mgr,
            handles: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start watching a formation's document store for changes.
    ///
    /// Spawns a background task that listens to the `ChangeStream` and
    /// publishes `CdcEvent`s via the CDC engine. After each successful
    /// publish, the change_hash is persisted as a cursor for deduplication.
    pub async fn watch_formation(
        &self,
        org_id: String,
        app_id: String,
        doc_store: Arc<dyn DocumentStore>,
    ) -> Result<()> {
        let key = (org_id.clone(), app_id.clone());

        // Don't double-watch
        let mut handles = self.handles.lock().await;
        if handles.contains_key(&key) {
            debug!(org_id = %org_id, app_id = %app_id, "Formation already watched, skipping");
            return Ok(());
        }

        // Observe all documents in the formation's collection
        let collection = format!("{}.{}", org_id, app_id);
        let mut stream = doc_store
            .observe(&collection, &Query::All)
            .with_context(|| format!("Failed to observe collection {collection}"))?;

        let engine = self.engine.clone();
        let tenant_mgr = self.tenant_mgr.clone();
        let task_org = org_id.clone();
        let task_app = app_id.clone();

        let handle = tokio::spawn(async move {
            info!(org_id = %task_org, app_id = %task_app, "CDC watcher started");

            while let Some(event) = stream.receiver.recv().await {
                match event {
                    ChangeEvent::Updated {
                        collection: _,
                        document,
                    } => {
                        let doc_id = document.id.clone().unwrap_or_else(|| "unknown".to_string());

                        let timestamp_ms = document
                            .updated_at
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);

                        let change_hash =
                            format!("{:x}", hash_fields(&doc_id, &document.fields, timestamp_ms));

                        // Deduplicate: skip if cursor matches this change_hash
                        if let Ok(Some(ref cursor)) =
                            tenant_mgr.get_cursor(&task_org, &task_app, &doc_id).await
                        {
                            if cursor == &change_hash {
                                debug!(
                                    doc_id = %doc_id,
                                    change_hash = %change_hash,
                                    "Skipping duplicate CDC event (cursor match)"
                                );
                                continue;
                            }
                        }

                        let cdc_event = CdcEvent {
                            org_id: task_org.clone(),
                            app_id: task_app.clone(),
                            document_id: doc_id,
                            change_hash,
                            actor_id: document
                                .fields
                                .get("_actor")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            timestamp_ms,
                            patches: serde_json::to_value(&document.fields)
                                .unwrap_or(serde_json::Value::Null),
                        };

                        if let Err(e) = engine.publish(&cdc_event).await {
                            warn!(
                                org_id = %task_org,
                                app_id = %task_app,
                                doc_id = %cdc_event.document_id,
                                error = %e,
                                "Failed to publish CDC event from watcher"
                            );
                            continue;
                        }

                        // Persist cursor after successful publish
                        if let Err(e) = tenant_mgr
                            .set_cursor(
                                &cdc_event.org_id,
                                &cdc_event.app_id,
                                &cdc_event.document_id,
                                &cdc_event.change_hash,
                            )
                            .await
                        {
                            warn!(
                                error = %e,
                                "Failed to persist CDC cursor (event was published)"
                            );
                        }
                    }
                    ChangeEvent::Removed {
                        collection: _,
                        doc_id,
                    } => {
                        let timestamp_ms = SystemTime::now()
                            .duration_since(SystemTime::UNIX_EPOCH)
                            .map(|d| d.as_millis() as u64)
                            .unwrap_or(0);

                        let change_hash =
                            format!("{:x}", hash_fields(&doc_id, &HashMap::new(), timestamp_ms));

                        let cdc_event = CdcEvent {
                            org_id: task_org.clone(),
                            app_id: task_app.clone(),
                            document_id: doc_id,
                            change_hash,
                            actor_id: "system".to_string(),
                            timestamp_ms,
                            patches: serde_json::json!({"_deleted": true}),
                        };

                        if let Err(e) = engine.publish(&cdc_event).await {
                            warn!(
                                org_id = %task_org,
                                app_id = %task_app,
                                error = %e,
                                "Failed to publish CDC removal event"
                            );
                            continue;
                        }

                        // Persist cursor for removal too
                        if let Err(e) = tenant_mgr
                            .set_cursor(
                                &cdc_event.org_id,
                                &cdc_event.app_id,
                                &cdc_event.document_id,
                                &cdc_event.change_hash,
                            )
                            .await
                        {
                            warn!(
                                error = %e,
                                "Failed to persist CDC cursor for removal"
                            );
                        }
                    }
                    ChangeEvent::Initial { documents } => {
                        debug!(
                            org_id = %task_org,
                            app_id = %task_app,
                            count = documents.len(),
                            "Received initial document snapshot (not emitting CDC events)"
                        );
                    }
                }
            }

            info!(org_id = %task_org, app_id = %task_app, "CDC watcher stream ended");
        });

        handles.insert(key, handle);
        info!(org_id = %org_id, app_id = %app_id, "CDC watcher registered");
        Ok(())
    }

    /// Stop watching a formation.
    pub async fn unwatch_formation(&self, org_id: &str, app_id: &str) {
        let key = (org_id.to_string(), app_id.to_string());
        let mut handles = self.handles.lock().await;
        if let Some(handle) = handles.remove(&key) {
            handle.abort();
            info!(org_id = %org_id, app_id = %app_id, "CDC watcher stopped");
        }
    }

    /// Stop all watchers.
    pub async fn shutdown(&self) {
        let mut handles = self.handles.lock().await;
        for ((org_id, app_id), handle) in handles.drain() {
            handle.abort();
            debug!(org_id = %org_id, app_id = %app_id, "CDC watcher aborted on shutdown");
        }
        info!("All CDC watchers stopped");
    }
}

/// Simple hash for change deduplication.
/// Combines doc_id, field count, and timestamp to produce a unique-enough hash.
fn hash_fields(
    doc_id: &str,
    fields: &HashMap<String, serde_json::Value>,
    timestamp_ms: u64,
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    doc_id.hash(&mut hasher);
    timestamp_ms.hash(&mut hasher);
    let mut keys: Vec<&String> = fields.keys().collect();
    keys.sort();
    for k in keys {
        k.hash(&mut hasher);
        if let Ok(v) = serde_json::to_string(&fields[k]) {
            v.hash(&mut hasher);
        }
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::time::SystemTime;

    // ── hash_fields tests ──────────────────────────────────────────

    #[test]
    fn hash_fields_deterministic_for_same_inputs() {
        let mut fields = HashMap::new();
        fields.insert("name".to_string(), Value::String("alice".to_string()));
        fields.insert("age".to_string(), Value::Number(30.into()));

        let h1 = hash_fields("doc-1", &fields, 1000);
        let h2 = hash_fields("doc-1", &fields, 1000);
        assert_eq!(h1, h2, "Same inputs must produce the same hash");
    }

    #[test]
    fn hash_fields_different_doc_ids_differ() {
        let fields = HashMap::new();
        let h1 = hash_fields("doc-a", &fields, 1000);
        let h2 = hash_fields("doc-b", &fields, 1000);
        assert_ne!(h1, h2, "Different doc_ids must produce different hashes");
    }

    #[test]
    fn hash_fields_different_timestamps_differ() {
        let fields = HashMap::new();
        let h1 = hash_fields("doc-1", &fields, 1000);
        let h2 = hash_fields("doc-1", &fields, 2000);
        assert_ne!(h1, h2, "Different timestamps must produce different hashes");
    }

    #[test]
    fn hash_fields_different_field_values_differ() {
        let mut f1 = HashMap::new();
        f1.insert("status".to_string(), Value::String("active".to_string()));

        let mut f2 = HashMap::new();
        f2.insert("status".to_string(), Value::String("inactive".to_string()));

        let h1 = hash_fields("doc-1", &f1, 1000);
        let h2 = hash_fields("doc-1", &f2, 1000);
        assert_ne!(
            h1, h2,
            "Different field values must produce different hashes"
        );
    }

    #[test]
    fn hash_fields_different_field_keys_differ() {
        let mut f1 = HashMap::new();
        f1.insert("a".to_string(), Value::Bool(true));

        let mut f2 = HashMap::new();
        f2.insert("b".to_string(), Value::Bool(true));

        let h1 = hash_fields("doc-1", &f1, 1000);
        let h2 = hash_fields("doc-1", &f2, 1000);
        assert_ne!(h1, h2, "Different field keys must produce different hashes");
    }

    #[test]
    fn hash_fields_order_independent() {
        // Insert keys in different orders; HashMap iteration order is
        // non-deterministic, but hash_fields sorts keys before hashing.
        let mut f1 = HashMap::new();
        f1.insert("z".to_string(), Value::Number(1.into()));
        f1.insert("a".to_string(), Value::Number(2.into()));
        f1.insert("m".to_string(), Value::Number(3.into()));

        let mut f2 = HashMap::new();
        f2.insert("a".to_string(), Value::Number(2.into()));
        f2.insert("m".to_string(), Value::Number(3.into()));
        f2.insert("z".to_string(), Value::Number(1.into()));

        let h1 = hash_fields("doc-1", &f1, 1000);
        let h2 = hash_fields("doc-1", &f2, 1000);
        assert_eq!(h1, h2, "Field insertion order must not affect the hash");
    }

    #[test]
    fn hash_fields_empty_fields() {
        let empty = HashMap::new();
        let h = hash_fields("doc-1", &empty, 1000);
        // Should not panic and should produce a non-zero hash
        assert_ne!(h, 0, "Hash of empty fields should be non-zero");
    }

    #[test]
    fn hash_fields_nested_json() {
        let mut fields = HashMap::new();
        fields.insert(
            "nested".to_string(),
            serde_json::json!({"inner": [1, 2, 3]}),
        );

        let h1 = hash_fields("doc-1", &fields, 1000);
        let h2 = hash_fields("doc-1", &fields, 1000);
        assert_eq!(h1, h2, "Nested JSON fields should hash deterministically");
    }

    // ── change_hash format tests ───────────────────────────────────

    #[test]
    fn change_hash_is_lowercase_hex() {
        let fields = HashMap::new();
        let h = hash_fields("doc-1", &fields, 12345);
        let hex_str = format!("{:x}", h);
        assert!(
            hex_str.chars().all(|c| c.is_ascii_hexdigit()),
            "Hash should format as hex: {hex_str}"
        );
        assert_eq!(
            hex_str,
            hex_str.to_lowercase(),
            "Hex hash should be lowercase"
        );
    }

    // ── CdcEvent construction from Updated variant ─────────────────

    #[test]
    fn cdc_event_actor_extracted_from_fields() {
        let mut fields = HashMap::new();
        fields.insert("_actor".to_string(), Value::String("peer-42".to_string()));
        fields.insert("data".to_string(), Value::Number(99.into()));

        let actor = fields
            .get("_actor")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        assert_eq!(actor, "peer-42");
    }

    #[test]
    fn cdc_event_actor_defaults_to_unknown() {
        let fields: HashMap<String, Value> = HashMap::new();

        let actor = fields
            .get("_actor")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        assert_eq!(actor, "unknown");
    }

    #[test]
    fn cdc_event_actor_non_string_falls_back_to_unknown() {
        let mut fields = HashMap::new();
        fields.insert("_actor".to_string(), Value::Number(123.into()));

        let actor = fields
            .get("_actor")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        assert_eq!(actor, "unknown");
    }

    // ── Timestamp extraction tests ─────────────────────────────────

    #[test]
    fn timestamp_conversion_from_system_time() {
        let now = SystemTime::now();
        let ts = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        assert!(ts > 0, "Current time should produce non-zero timestamp");
        // Sanity: timestamp should be after 2020-01-01
        assert!(ts > 1_577_836_800_000);
    }

    #[test]
    fn timestamp_before_epoch_yields_zero() {
        // SystemTime::UNIX_EPOCH minus something would err, so the unwrap_or(0) path
        // is exercised whenever duration_since fails.
        let result = SystemTime::UNIX_EPOCH
            .duration_since(SystemTime::now())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        assert_eq!(result, 0, "Failed duration_since should default to 0");
    }

    // ── Patches serialization tests ────────────────────────────────

    #[test]
    fn patches_serialize_fields_to_json() {
        let mut fields = HashMap::new();
        fields.insert("status".to_string(), Value::String("shipped".to_string()));
        fields.insert("count".to_string(), Value::Number(42.into()));

        let patches = serde_json::to_value(&fields).unwrap_or(Value::Null);
        assert!(patches.is_object());
        assert_eq!(patches["status"], "shipped");
        assert_eq!(patches["count"], 42);
    }

    #[test]
    fn removal_patches_contain_deleted_flag() {
        let patches = serde_json::json!({"_deleted": true});
        assert_eq!(patches["_deleted"], true);
    }

    // ── Collection name formatting ─────────────────────────────────

    #[test]
    fn collection_name_format() {
        let org_id = "acme";
        let app_id = "logistics";
        let collection = format!("{}.{}", org_id, app_id);
        assert_eq!(collection, "acme.logistics");
    }

    // ── FormationKey uniqueness ────────────────────────────────────

    #[test]
    fn formation_key_same_org_different_app() {
        let k1: FormationKey = ("org".to_string(), "app-a".to_string());
        let k2: FormationKey = ("org".to_string(), "app-b".to_string());
        assert_ne!(k1, k2);
    }

    #[test]
    fn formation_key_different_org_same_app() {
        let k1: FormationKey = ("org-a".to_string(), "app".to_string());
        let k2: FormationKey = ("org-b".to_string(), "app".to_string());
        assert_ne!(k1, k2);
    }

    #[test]
    fn formation_key_equality() {
        let k1: FormationKey = ("org".to_string(), "app".to_string());
        let k2: FormationKey = ("org".to_string(), "app".to_string());
        assert_eq!(k1, k2);
    }

    // ── Document ID extraction ─────────────────────────────────────

    #[test]
    fn doc_id_present() {
        let id: Option<String> = Some("order-001".to_string());
        let doc_id = id.unwrap_or_else(|| "unknown".to_string());
        assert_eq!(doc_id, "order-001");
    }

    #[test]
    fn doc_id_missing_falls_back_to_unknown() {
        let id: Option<String> = None;
        let doc_id = id.unwrap_or_else(|| "unknown".to_string());
        assert_eq!(doc_id, "unknown");
    }

    // ── Watcher double-watch and lifecycle (async) ─────────────────

    mod lifecycle {
        use super::*;
        use crate::cdc::CdcEngine;
        use crate::config::{CdcConfig, GatewayConfig, StorageConfig};
        use crate::tenant::TenantManager;
        use peat_mesh::sync::in_memory::InMemoryBackend;
        use peat_mesh::sync::traits::DataSyncBackend;
        use peat_mesh::sync::types::{BackendConfig, TransportConfig};

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

        async fn make_doc_store(
            app_id: &str,
        ) -> (
            InMemoryBackend,
            Arc<dyn peat_mesh::sync::traits::DocumentStore>,
        ) {
            let backend = InMemoryBackend::new();
            let config = BackendConfig {
                app_id: app_id.to_string(),
                persistence_dir: std::path::PathBuf::from("/tmp/peat-unit-test"),
                shared_key: None,
                transport: TransportConfig::default(),
                extra: HashMap::new(),
            };
            backend.initialize(config).await.unwrap();
            let doc_store = backend.document_store();
            (backend, doc_store)
        }

        #[tokio::test]
        async fn double_watch_returns_ok_without_spawning_second_task() {
            let (tenant_mgr, engine, _dir) = setup().await;
            let (_be, store) = make_doc_store("app1").await;

            let watcher = CdcWatcher::new(engine, tenant_mgr);
            watcher
                .watch_formation("org1".into(), "app1".into(), store.clone())
                .await
                .unwrap();

            // Second call with same key should succeed (no-op)
            let result = watcher
                .watch_formation("org1".into(), "app1".into(), store.clone())
                .await;
            assert!(result.is_ok(), "Double watch should not error");

            // Should have exactly one handle registered
            let handles = watcher.handles.lock().await;
            assert_eq!(handles.len(), 1);

            drop(handles);
            watcher.shutdown().await;
        }

        #[tokio::test]
        async fn different_formations_get_separate_handles() {
            let (tenant_mgr, engine, _dir) = setup().await;
            let (_be1, store1) = make_doc_store("app1").await;
            let (_be2, store2) = make_doc_store("app2").await;

            let watcher = CdcWatcher::new(engine, tenant_mgr);
            watcher
                .watch_formation("org1".into(), "app1".into(), store1)
                .await
                .unwrap();
            watcher
                .watch_formation("org1".into(), "app2".into(), store2)
                .await
                .unwrap();

            let handles = watcher.handles.lock().await;
            assert_eq!(handles.len(), 2);

            drop(handles);
            watcher.shutdown().await;
        }

        #[tokio::test]
        async fn unwatch_removes_handle() {
            let (tenant_mgr, engine, _dir) = setup().await;
            let (_be, store) = make_doc_store("app1").await;

            let watcher = CdcWatcher::new(engine, tenant_mgr);
            watcher
                .watch_formation("org1".into(), "app1".into(), store)
                .await
                .unwrap();

            assert_eq!(watcher.handles.lock().await.len(), 1);

            watcher.unwatch_formation("org1", "app1").await;

            assert_eq!(watcher.handles.lock().await.len(), 0);
        }

        #[tokio::test]
        async fn unwatch_nonexistent_is_noop() {
            let (tenant_mgr, engine, _dir) = setup().await;
            let watcher = CdcWatcher::new(engine, tenant_mgr);

            // Should not panic
            watcher.unwatch_formation("org1", "app1").await;
            assert_eq!(watcher.handles.lock().await.len(), 0);
        }

        #[tokio::test]
        async fn shutdown_clears_all_handles() {
            let (tenant_mgr, engine, _dir) = setup().await;
            let (_be1, store1) = make_doc_store("app1").await;
            let (_be2, store2) = make_doc_store("app2").await;

            let watcher = CdcWatcher::new(engine, tenant_mgr);
            watcher
                .watch_formation("org1".into(), "app1".into(), store1)
                .await
                .unwrap();
            watcher
                .watch_formation("org2".into(), "app2".into(), store2)
                .await
                .unwrap();

            assert_eq!(watcher.handles.lock().await.len(), 2);

            watcher.shutdown().await;

            assert_eq!(watcher.handles.lock().await.len(), 0);
        }

        #[tokio::test]
        async fn watch_after_unwatch_re_registers() {
            let (tenant_mgr, engine, _dir) = setup().await;
            let (_be1, store1) = make_doc_store("app1").await;
            let (_be2, store2) = make_doc_store("app1-v2").await;

            let watcher = CdcWatcher::new(engine, tenant_mgr);
            watcher
                .watch_formation("org1".into(), "app1".into(), store1)
                .await
                .unwrap();

            watcher.unwatch_formation("org1", "app1").await;
            assert_eq!(watcher.handles.lock().await.len(), 0);

            // Re-register same key with new store
            watcher
                .watch_formation("org1".into(), "app1".into(), store2)
                .await
                .unwrap();
            assert_eq!(watcher.handles.lock().await.len(), 1);

            watcher.shutdown().await;
        }
    }
}
