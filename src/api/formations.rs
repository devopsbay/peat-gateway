use std::collections::HashMap;
use std::sync::Arc;

use axum::{
    extract::{Path, State},
    routing::get,
    Json, Router,
};
use peat_mesh::broker::MeshBrokerState;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::tenant::models::PeerInfo;
use crate::tenant::TenantManager;

type ApiError = (axum::http::StatusCode, String);
type BrokerMap = HashMap<(String, String), Arc<dyn MeshBrokerState>>;

fn not_found(e: anyhow::Error) -> ApiError {
    (axum::http::StatusCode::NOT_FOUND, e.to_string())
}

fn internal(e: anyhow::Error) -> ApiError {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

/// Registry mapping (org_id, app_id) to live mesh broker state.
///
/// The gateway control plane does not run mesh nodes itself — external mesh
/// nodes register their broker state handles here so the API can query them.
#[derive(Clone, Default)]
pub struct MeshStateRegistry {
    inner: Arc<RwLock<BrokerMap>>,
}

impl MeshStateRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a mesh broker state handle for a formation.
    pub async fn register(
        &self,
        org_id: impl Into<String>,
        app_id: impl Into<String>,
        state: Arc<dyn MeshBrokerState>,
    ) {
        self.inner
            .write()
            .await
            .insert((org_id.into(), app_id.into()), state);
    }

    /// Remove a formation's broker state handle.
    pub async fn deregister(&self, org_id: &str, app_id: &str) {
        self.inner
            .write()
            .await
            .remove(&(org_id.to_string(), app_id.to_string()));
    }

    /// Look up the broker state for a formation.
    pub async fn get(&self, org_id: &str, app_id: &str) -> Option<Arc<dyn MeshBrokerState>> {
        self.inner
            .read()
            .await
            .get(&(org_id.to_string(), app_id.to_string()))
            .cloned()
    }
}

/// Combined state for formation endpoints.
#[derive(Clone)]
pub struct FormationState {
    pub mgr: TenantManager,
    pub mesh: MeshStateRegistry,
}

// --- Peers (read-only, sourced from mesh) ---

async fn list_peers(
    State(state): State<FormationState>,
    Path((org_id, app_id)): Path<(String, String)>,
) -> Result<Json<Vec<PeerInfo>>, ApiError> {
    // Verify org + formation exist
    state
        .mgr
        .get_formation(&org_id, &app_id)
        .await
        .map_err(not_found)?;

    let broker = match state.mesh.get(&org_id, &app_id).await {
        Some(b) => b,
        None => return Ok(Json(Vec::new())),
    };

    let summaries = broker.list_peers().await;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let peers: Vec<PeerInfo> = summaries
        .into_iter()
        .map(|s| PeerInfo {
            peer_id: s.id,
            app_id: app_id.clone(),
            status: if s.connected {
                crate::tenant::models::PeerStatus::Connected
            } else {
                crate::tenant::models::PeerStatus::Disconnected
            },
            last_seen: now_ms,
        })
        .collect();

    Ok(Json(peers))
}

// --- Documents (read-only, sourced from mesh) ---

#[derive(Serialize)]
struct DocumentSummary {
    doc_id: String,
    key_count: u64,
    last_modified: u64,
}

async fn list_documents(
    State(state): State<FormationState>,
    Path((org_id, app_id)): Path<(String, String)>,
) -> Result<Json<Vec<DocumentSummary>>, ApiError> {
    state
        .mgr
        .get_formation(&org_id, &app_id)
        .await
        .map_err(not_found)?;

    let broker = match state.mesh.get(&org_id, &app_id).await {
        Some(b) => b,
        None => return Ok(Json(Vec::new())),
    };

    // First prefer the historical gateway convention of using the app_id as
    // the collection name. If the broker doesn't expose that collection,
    // aggregate the default PEAT/tropiOS collections so the endpoint still
    // surfaces live mesh documents.
    let docs = if let Some(d) = broker.list_documents(&app_id).await {
        d
    } else {
        let mut aggregated = Vec::new();
        for collection in ["cot-broadcast", "contacts", "markers", "missions"] {
            if let Some(mut docs) = broker.list_documents(collection).await {
                for doc in &mut docs {
                    if let Some(obj) = doc.as_object_mut() {
                        obj.entry("_collection".to_string())
                            .or_insert_with(|| serde_json::Value::String(collection.to_string()));
                    }
                }
                aggregated.extend(docs);
            }
        }
        if aggregated.is_empty() {
            return Ok(Json(Vec::new()));
        }
        aggregated
    };

    let summaries: Vec<DocumentSummary> = docs
        .into_iter()
        .map(|val| {
            let doc_id = val
                .get("_id")
                .or_else(|| val.get("uid"))
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let key_count = val.as_object().map(|m| m.len() as u64).unwrap_or(0);

            let last_modified = val
                .get("_last_modified")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            DocumentSummary {
                doc_id,
                key_count,
                last_modified,
            }
        })
        .collect();

    Ok(Json(summaries))
}

// --- Certificates (peer identity certs managed by mesh) ---

#[derive(Serialize)]
struct CertificateSummary {
    peer_id: String,
    fingerprint: String,
    issued_at: u64,
    expires_at: u64,
    revoked: bool,
}

async fn list_certificates(
    State(state): State<FormationState>,
    Path((org_id, app_id)): Path<(String, String)>,
) -> Result<Json<Vec<CertificateSummary>>, ApiError> {
    state
        .mgr
        .get_formation(&org_id, &app_id)
        .await
        .map_err(not_found)?;

    // Load the genesis to get the root authority certificate
    let genesis = state
        .mgr
        .load_genesis(&org_id, &app_id)
        .await
        .map_err(internal)?;

    let root_cert = genesis.root_certificate("authority-0");
    let authority_fingerprint = hex::encode(&root_cert.subject_public_key[..8]);

    let mut certs = vec![CertificateSummary {
        peer_id: root_cert.node_id.clone(),
        fingerprint: authority_fingerprint,
        issued_at: root_cert.issued_at_ms,
        expires_at: root_cert.expires_at_ms,
        revoked: false,
    }];

    // Include approved enrollments from the audit log as issued certificates
    let audit_entries = state
        .mgr
        .list_audit(&org_id, Some(&app_id), 1000)
        .await
        .map_err(internal)?;

    for entry in audit_entries {
        if let crate::tenant::models::EnrollmentDecision::Approved { .. } = &entry.decision {
            let fingerprint = hex::encode(&entry.subject.as_bytes()[..8.min(entry.subject.len())]);
            certs.push(CertificateSummary {
                peer_id: entry.subject.clone(),
                fingerprint,
                issued_at: entry.timestamp_ms,
                expires_at: 0,
                revoked: false,
            });
        }
    }

    Ok(Json(certs))
}

pub fn router(tenant_mgr: TenantManager) -> Router {
    router_with_mesh(tenant_mgr, MeshStateRegistry::new())
}

pub fn router_with_mesh(tenant_mgr: TenantManager, mesh: MeshStateRegistry) -> Router {
    let state = FormationState {
        mgr: tenant_mgr,
        mesh,
    };
    Router::new()
        .route("/:org_id/formations/:app_id/peers", get(list_peers))
        .route("/:org_id/formations/:app_id/documents", get(list_documents))
        .route(
            "/:org_id/formations/:app_id/certificates",
            get(list_certificates),
        )
        .with_state(state)
}
