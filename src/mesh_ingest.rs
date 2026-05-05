use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use peat_mesh::broker::state::{ReadinessCheck, ReadinessResponse};
use peat_mesh::broker::{MeshBrokerState, MeshEvent, MeshNodeInfo, PeerSummary, TopologySummary};
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::broadcast;
use tracing::{debug, warn};

use crate::api::formations::MeshStateRegistry;
use crate::cdc::CdcEngine;
use crate::config::MeshBrokerMapping;
use crate::tenant::models::CdcEvent;

#[derive(Clone)]
pub struct MeshIngestManager {
    registry: MeshStateRegistry,
    client: Client,
    poll_interval: Duration,
    cdc_engine: Option<CdcEngine>,
}

impl MeshIngestManager {
    pub fn new(registry: MeshStateRegistry, poll_interval: Duration) -> Self {
        Self {
            registry,
            client: Client::new(),
            poll_interval,
            cdc_engine: None,
        }
    }

    /// Attach a CDC engine so document changes detected during polling are
    /// forwarded to all configured sinks (e.g. the trop-server webhook).
    pub fn with_cdc(mut self, engine: CdcEngine) -> Self {
        self.cdc_engine = Some(engine);
        self
    }

    pub async fn register_remote_broker(&self, mapping: MeshBrokerMapping) {
        let state = Arc::new(RemoteBrokerState::new(
            self.client.clone(),
            mapping.clone(),
            self.poll_interval,
            self.cdc_engine.clone(),
        ));

        state.spawn_refresh_loop();
        self.registry
            .register(mapping.org_id, mapping.app_id, state)
            .await;
    }
}

#[derive(Clone)]
struct Snapshot {
    node_info: MeshNodeInfo,
    topology: TopologySummary,
    readiness: ReadinessResponse,
    peers: Vec<PeerSummary>,
    documents: HashMap<String, Vec<Value>>,
    last_sync_ms: Option<u64>,
    last_error: Option<String>,
}

impl Snapshot {
    fn new(node_id: String) -> Self {
        Self {
            node_info: MeshNodeInfo {
                node_id: node_id.clone(),
                uptime_secs: 0,
                version: "remote-broker-pending".into(),
            },
            topology: TopologySummary {
                peer_count: 0,
                role: "standalone".into(),
                hierarchy_level: 0,
            },
            readiness: ReadinessResponse {
                ready: false,
                node_id,
                checks: vec![ReadinessCheck {
                    name: "remote-broker".into(),
                    ready: false,
                    message: Some("waiting for first successful poll".into()),
                }],
            },
            peers: vec![],
            documents: HashMap::new(),
            last_sync_ms: None,
            last_error: None,
        }
    }
}

pub struct RemoteBrokerState {
    client: Client,
    mapping: MeshBrokerMapping,
    poll_interval: Duration,
    snapshot: Arc<RwLock<Snapshot>>,
    events_tx: broadcast::Sender<MeshEvent>,
    cdc_engine: Option<CdcEngine>,
}

impl RemoteBrokerState {
    pub fn new(
        client: Client,
        mapping: MeshBrokerMapping,
        poll_interval: Duration,
        cdc_engine: Option<CdcEngine>,
    ) -> Self {
        let (events_tx, _) = broadcast::channel(256);
        let snapshot = Arc::new(RwLock::new(Snapshot::new(format!(
            "{}:{}",
            mapping.org_id, mapping.app_id
        ))));

        Self {
            client,
            mapping,
            poll_interval,
            snapshot,
            events_tx,
            cdc_engine,
        }
    }

    pub fn spawn_refresh_loop(self: &Arc<Self>) {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            if let Err(err) = this.refresh_once().await {
                this.record_error(err.to_string());
            }

            let mut ticker = tokio::time::interval(this.poll_interval);
            loop {
                ticker.tick().await;
                if let Err(err) = this.refresh_once().await {
                    warn!(
                        org_id = %this.mapping.org_id,
                        app_id = %this.mapping.app_id,
                        broker = %this.mapping.base_url,
                        error = %err,
                        "remote mesh broker refresh failed"
                    );
                    this.record_error(err.to_string());
                }
            }
        });
    }

    async fn refresh_once(&self) -> Result<()> {
        let node_dto: NodeInfoDto = self.get_json("/api/v1/node").await?;
        let node_info = MeshNodeInfo {
            node_id: node_dto.node_id,
            uptime_secs: node_dto.uptime_secs,
            version: node_dto.version,
        };

        let topo_dto: TopologyDto = self.get_json("/api/v1/topology").await?;
        let topology = TopologySummary {
            peer_count: topo_dto.peer_count,
            role: topo_dto.role,
            hierarchy_level: topo_dto.hierarchy_level,
        };

        let readiness = match self.get_json::<ReadinessDto>("/api/v1/ready").await {
            Ok(dto) => ReadinessResponse {
                ready: dto.ready,
                node_id: dto.node_id,
                checks: dto
                    .checks
                    .into_iter()
                    .map(|c| ReadinessCheck {
                        name: c.name,
                        ready: c.ready,
                        message: c.message,
                    })
                    .collect(),
            },
            Err(err) => ReadinessResponse {
                ready: false,
                node_id: node_info.node_id.clone(),
                checks: vec![ReadinessCheck {
                    name: "remote-broker".into(),
                    ready: false,
                    message: Some(format!("ready probe failed: {err}")),
                }],
            },
        };
        let peers_resp: PeersEnvelope = self.get_json("/api/v1/peers").await?;

        let mut documents = HashMap::new();
        for collection in &self.mapping.collections {
            match self
                .get_json::<DocumentsEnvelope>(&format!("/api/v1/documents/{collection}"))
                .await
            {
                Ok(resp) => {
                    documents.insert(collection.clone(), resp.documents);
                }
                Err(err) => {
                    debug!(
                        org_id = %self.mapping.org_id,
                        app_id = %self.mapping.app_id,
                        collection = %collection,
                        broker = %self.mapping.base_url,
                        error = %err,
                        "remote broker collection unavailable"
                    );
                }
            }
        }

        let peers: Vec<PeerSummary> = peers_resp
            .peers
            .into_iter()
            .map(|p| PeerSummary {
                id: p.id,
                connected: p.connected,
                state: p.state,
                rtt_ms: p.rtt_ms,
            })
            .collect();

        let last_sync_ms = now_ms();
        let new_snapshot = Snapshot {
            node_info,
            topology,
            readiness,
            peers,
            documents,
            last_sync_ms: Some(last_sync_ms),
            last_error: None,
        };

        // Publish CDC events BEFORE swapping snapshot so old state is still readable
        if let Some(ref engine) = self.cdc_engine {
            self.publish_cdc_diffs(engine, &new_snapshot, last_sync_ms)
                .await;
        }

        self.emit_diffs(&new_snapshot);
        let mut snapshot = self.snapshot.write().unwrap_or_else(|e| e.into_inner());
        *snapshot = new_snapshot;
        Ok(())
    }

    /// Compare current snapshot to `new_snapshot` and publish a `CdcEvent` for
    /// every document that is new or whose content has changed.
    async fn publish_cdc_diffs(
        &self,
        engine: &CdcEngine,
        new_snapshot: &Snapshot,
        timestamp_ms: u64,
    ) {
        let old_docs = self
            .snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .documents
            .clone();

        tracing::debug!(
            collections = new_snapshot.documents.len(),
            "publish_cdc_diffs called"
        );
        for (collection, new_docs) in &new_snapshot.documents {
            tracing::debug!(collection = %collection, doc_count = new_docs.len(), "checking collection for CDC diffs");
            let old_by_id: HashMap<String, u64> = old_docs
                .get(collection)
                .into_iter()
                .flatten()
                .filter_map(|d| document_id(d).map(|id| (id, doc_content_hash(d))))
                .collect();

            for doc in new_docs {
                let Some(doc_id) = document_id(doc) else {
                    continue;
                };

                let new_hash = doc_content_hash(doc);
                let old_hash = old_by_id.get(&doc_id).copied();

                // Skip if unchanged
                if old_hash == Some(new_hash) {
                    continue;
                }

                let change_hash = format!("{new_hash:016x}");
                let actor_id = doc
                    .get("_actor")
                    .and_then(|v| v.as_str())
                    .unwrap_or("remote-broker")
                    .to_string();

                tracing::info!(collection = %collection, doc_id = %doc_id, "CDC event: document changed, publishing");
                let event = CdcEvent {
                    org_id: self.mapping.org_id.clone(),
                    app_id: self.mapping.app_id.clone(),
                    document_id: format!("{collection}/{doc_id}"),
                    change_hash,
                    actor_id,
                    timestamp_ms,
                    patches: doc.clone(),
                };

                if let Err(e) = engine.publish(&event).await {
                    warn!(
                        org_id = %self.mapping.org_id,
                        app_id = %self.mapping.app_id,
                        doc_id = %doc_id,
                        collection = %collection,
                        error = %e,
                        "Failed to publish CDC event for remote broker document"
                    );
                }
            }
        }
    }

    async fn get_json<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T> {
        let url = format!("{}{}", self.mapping.base_url, path);
        let response = self.client.get(url).send().await?.error_for_status()?;
        Ok(response.json::<T>().await?)
    }

    fn emit_diffs(&self, new_snapshot: &Snapshot) {
        let old_snapshot = self
            .snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();

        let old_peers: HashSet<String> = old_snapshot.peers.into_iter().map(|p| p.id).collect();
        let new_peers: HashSet<String> = new_snapshot.peers.iter().map(|p| p.id.clone()).collect();

        for peer_id in new_peers.difference(&old_peers) {
            let _ = self.events_tx.send(MeshEvent::PeerConnected {
                peer_id: peer_id.clone(),
            });
        }
        for peer_id in old_peers.difference(&new_peers) {
            let _ = self.events_tx.send(MeshEvent::PeerDisconnected {
                peer_id: peer_id.clone(),
                reason: "missing from remote broker snapshot".into(),
            });
        }

        if old_snapshot.topology.peer_count != new_snapshot.topology.peer_count
            || old_snapshot.topology.role != new_snapshot.topology.role
        {
            let _ = self.events_tx.send(MeshEvent::TopologyChanged {
                new_role: new_snapshot.topology.role.clone(),
                peer_count: new_snapshot.topology.peer_count,
            });
        }

        for (collection, docs) in &new_snapshot.documents {
            let old_ids: HashSet<String> = old_snapshot
                .documents
                .get(collection)
                .into_iter()
                .flatten()
                .filter_map(document_id)
                .collect();
            let new_ids: HashSet<String> = docs.iter().filter_map(document_id).collect();

            for doc_id in new_ids.difference(&old_ids) {
                let _ = self.events_tx.send(MeshEvent::SyncEvent {
                    collection: collection.clone(),
                    doc_id: doc_id.clone(),
                    action: "upsert".into(),
                });
            }
        }
    }

    fn record_error(&self, error: String) {
        let mut snapshot = self.snapshot.write().unwrap_or_else(|e| e.into_inner());
        snapshot.last_error = Some(error.clone());
        snapshot.readiness = ReadinessResponse {
            ready: false,
            node_id: snapshot.node_info.node_id.clone(),
            checks: vec![ReadinessCheck {
                name: "remote-broker".into(),
                ready: false,
                message: Some(error),
            }],
        };
    }
}

#[async_trait::async_trait]
impl MeshBrokerState for RemoteBrokerState {
    fn node_info(&self) -> MeshNodeInfo {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .node_info
            .clone()
    }

    async fn list_peers(&self) -> Vec<PeerSummary> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .clone()
    }

    async fn get_peer(&self, id: &str) -> Option<PeerSummary> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .peers
            .iter()
            .find(|peer| peer.id == id)
            .cloned()
    }

    fn topology(&self) -> TopologySummary {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .topology
            .clone()
    }

    fn subscribe_events(&self) -> broadcast::Receiver<MeshEvent> {
        self.events_tx.subscribe()
    }

    fn readiness(&self) -> ReadinessResponse {
        let snapshot = self.snapshot.read().unwrap_or_else(|e| e.into_inner());
        let mut readiness = snapshot.readiness.clone();
        if let Some(last_sync_ms) = snapshot.last_sync_ms {
            readiness.checks.push(ReadinessCheck {
                name: "last-sync-ms".into(),
                ready: true,
                message: Some(last_sync_ms.to_string()),
            });
        }
        readiness
    }

    async fn list_documents(&self, collection: &str) -> Option<Vec<Value>> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .documents
            .get(collection)
            .cloned()
    }

    async fn get_document(&self, collection: &str, id: &str) -> Option<Value> {
        self.snapshot
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .documents
            .get(collection)
            .and_then(|docs| {
                docs.iter()
                    .find(|doc| document_id(doc).as_deref() == Some(id))
                    .cloned()
            })
    }
}

// Local DTOs for HTTP deserialization — peat_mesh broker types only derive
// Serialize, not Deserialize, so we deserialize into these then convert.

#[derive(Debug, Deserialize)]
struct NodeInfoDto {
    node_id: String,
    uptime_secs: u64,
    version: String,
}

#[derive(Debug, Deserialize)]
struct TopologyDto {
    peer_count: usize,
    role: String,
    hierarchy_level: u32,
}

#[derive(Debug, Deserialize)]
struct ReadinessDto {
    ready: bool,
    node_id: String,
    checks: Vec<ReadinessCheckDto>,
}

#[derive(Debug, Deserialize)]
struct ReadinessCheckDto {
    name: String,
    ready: bool,
    message: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PeerDto {
    id: String,
    connected: bool,
    state: String,
    rtt_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PeersEnvelope {
    peers: Vec<PeerDto>,
}

#[derive(Debug, Deserialize)]
struct DocumentsEnvelope {
    documents: Vec<Value>,
}

fn document_id(doc: &Value) -> Option<String> {
    doc.get("_id")
        .or_else(|| doc.get("uid"))
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

fn doc_content_hash(doc: &Value) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    if let Ok(s) = serde_json::to_string(doc) {
        s.hash(&mut hasher);
    }
    hasher.finish()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
