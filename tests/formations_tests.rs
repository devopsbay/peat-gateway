use std::net::SocketAddr;
use std::sync::Arc;

use peat_gateway::api;
use peat_gateway::api::formations::MeshStateRegistry;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::TenantManager;
use peat_mesh::broker::{MeshBrokerState, MeshEvent, MeshNodeInfo, PeerSummary, TopologySummary};
use reqwest::{Client, StatusCode};
use serde_json::{json, Value};
use tokio::sync::broadcast;

/// Mock mesh broker state for testing.
struct MockBrokerState {
    tx: broadcast::Sender<MeshEvent>,
    peers: Vec<PeerSummary>,
    documents: Option<Vec<Value>>,
}

impl MockBrokerState {
    fn empty() -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            tx,
            peers: vec![],
            documents: None,
        }
    }

    fn with_peers(peers: Vec<PeerSummary>) -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            tx,
            peers,
            documents: None,
        }
    }

    fn with_documents(docs: Vec<Value>) -> Self {
        let (tx, _) = broadcast::channel(16);
        Self {
            tx,
            peers: vec![],
            documents: Some(docs),
        }
    }
}

#[async_trait::async_trait]
impl MeshBrokerState for MockBrokerState {
    fn node_info(&self) -> MeshNodeInfo {
        MeshNodeInfo {
            node_id: "test-node".into(),
            uptime_secs: 0,
            version: "0.0.0".into(),
        }
    }

    async fn list_peers(&self) -> Vec<PeerSummary> {
        self.peers.clone()
    }

    async fn get_peer(&self, id: &str) -> Option<PeerSummary> {
        self.peers.iter().find(|p| p.id == id).cloned()
    }

    fn topology(&self) -> TopologySummary {
        TopologySummary {
            peer_count: self.peers.len(),
            role: "standalone".into(),
            hierarchy_level: 0,
        }
    }

    fn subscribe_events(&self) -> broadcast::Receiver<MeshEvent> {
        self.tx.subscribe()
    }

    async fn list_documents(&self, _collection: &str) -> Option<Vec<Value>> {
        self.documents.clone()
    }

    async fn get_document(&self, _collection: &str, _id: &str) -> Option<Value> {
        None
    }
}

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

async fn spawn_app_with_mesh(
    registry: MeshStateRegistry,
) -> (Client, String, tempfile::TempDir, TenantManager) {
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
    let _prometheus_handle = api::install_prometheus_recorder();

    // Build the app with our custom formations router
    let admin_routes = axum::Router::new().nest(
        "/orgs",
        peat_gateway::api::formations::router_with_mesh(tenant_mgr.clone(), registry),
    );

    let app: axum::Router = axum::Router::new().merge(admin_routes);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();

    let mgr_clone = tenant_mgr.clone();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    let base = format!("http://{}", addr);
    (client, base, dir, mgr_clone)
}

/// Helper to create an org and formation via the TenantManager.
async fn create_org_and_formation(mgr: &TenantManager, org_id: &str, app_id: &str) {
    mgr.create_org(org_id.to_string(), format!("{} Corp", org_id))
        .await
        .unwrap();
    mgr.create_formation(
        org_id,
        app_id.to_string(),
        peat_gateway::tenant::models::EnrollmentPolicy::Controlled,
    )
    .await
    .unwrap();
}

// --- Peer endpoint tests ---

#[tokio::test]
async fn list_peers_returns_404_for_unknown_formation() {
    let (client, base, _dir) = spawn_app().await;

    let resp = client
        .get(format!("{base}/orgs/ghost/formations/noapp/peers"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_peers_returns_empty_without_broker() {
    let registry = MeshStateRegistry::new();
    let (client, base, _dir, mgr) = spawn_app_with_mesh(registry).await;

    create_org_and_formation(&mgr, "acme", "myapp").await;

    let resp = client
        .get(format!("{base}/orgs/acme/formations/myapp/peers"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Vec<Value> = resp.json().await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn list_peers_returns_broker_peers() {
    let registry = MeshStateRegistry::new();
    let mock = MockBrokerState::with_peers(vec![
        PeerSummary {
            id: "peer-1".into(),
            connected: true,
            state: "active".into(),
            rtt_ms: Some(10),
        },
        PeerSummary {
            id: "peer-2".into(),
            connected: false,
            state: "disconnected".into(),
            rtt_ms: None,
        },
    ]);
    registry.register("acme", "myapp", Arc::new(mock)).await;

    let (client, base, _dir, mgr) = spawn_app_with_mesh(registry).await;
    create_org_and_formation(&mgr, "acme", "myapp").await;

    let resp = client
        .get(format!("{base}/orgs/acme/formations/myapp/peers"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(body.len(), 2);
    assert_eq!(body[0]["peer_id"], "peer-1");
    assert_eq!(body[0]["status"], "Connected");
    assert_eq!(body[1]["peer_id"], "peer-2");
    assert_eq!(body[1]["status"], "Disconnected");
}

// --- Document endpoint tests ---

#[tokio::test]
async fn list_documents_returns_empty_without_broker() {
    let registry = MeshStateRegistry::new();
    let (client, base, _dir, mgr) = spawn_app_with_mesh(registry).await;

    create_org_and_formation(&mgr, "acme", "myapp").await;

    let resp = client
        .get(format!("{base}/orgs/acme/formations/myapp/documents"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Vec<Value> = resp.json().await.unwrap();
    assert!(body.is_empty());
}

#[tokio::test]
async fn list_documents_returns_broker_documents() {
    let registry = MeshStateRegistry::new();
    let mock = MockBrokerState::with_documents(vec![
        json!({"_id": "doc1", "name": "first", "value": 42}),
        json!({"_id": "doc2", "name": "second", "_last_modified": 1700000000000u64}),
    ]);
    registry.register("acme", "myapp", Arc::new(mock)).await;

    let (client, base, _dir, mgr) = spawn_app_with_mesh(registry).await;
    create_org_and_formation(&mgr, "acme", "myapp").await;

    let resp = client
        .get(format!("{base}/orgs/acme/formations/myapp/documents"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Vec<Value> = resp.json().await.unwrap();
    assert_eq!(body.len(), 2);
    assert_eq!(body[0]["doc_id"], "doc1");
    assert!(body[0]["key_count"].as_u64().unwrap() > 0);
    assert_eq!(body[1]["doc_id"], "doc2");
    assert_eq!(body[1]["last_modified"], 1700000000000u64);
}

// --- Certificate endpoint tests ---

#[tokio::test]
async fn list_certificates_returns_root_cert() {
    let registry = MeshStateRegistry::new();
    let (client, base, _dir, mgr) = spawn_app_with_mesh(registry).await;

    create_org_and_formation(&mgr, "acme", "myapp").await;

    let resp = client
        .get(format!("{base}/orgs/acme/formations/myapp/certificates"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body: Vec<Value> = resp.json().await.unwrap();
    // Should contain at least the root authority cert
    assert!(!body.is_empty());
    assert_eq!(body[0]["peer_id"], "authority-0");
    assert!(!body[0]["fingerprint"].as_str().unwrap().is_empty());
    assert!(body[0]["issued_at"].as_u64().unwrap() > 0);
    // Root cert never expires
    assert_eq!(body[0]["expires_at"], 0);
    assert_eq!(body[0]["revoked"], false);
}

#[tokio::test]
async fn list_certificates_returns_404_for_unknown_formation() {
    let (client, base, _dir) = spawn_app().await;

    let resp = client
        .get(format!("{base}/orgs/ghost/formations/noapp/certificates"))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// --- MeshStateRegistry unit tests ---

#[tokio::test]
async fn registry_register_and_get() {
    let registry = MeshStateRegistry::new();
    assert!(registry.get("org", "app").await.is_none());

    let mock = Arc::new(MockBrokerState::empty());
    registry.register("org", "app", mock).await;

    assert!(registry.get("org", "app").await.is_some());
    assert!(registry.get("org", "other").await.is_none());
}

#[tokio::test]
async fn registry_deregister() {
    let registry = MeshStateRegistry::new();

    let mock = Arc::new(MockBrokerState::empty());
    registry.register("org", "app", mock).await;
    assert!(registry.get("org", "app").await.is_some());

    registry.deregister("org", "app").await;
    assert!(registry.get("org", "app").await.is_none());
}
