use std::net::SocketAddr;

use axum::{extract::State, routing::get, Json, Router};
use peat_gateway::api;
use peat_gateway::api::formations::MeshStateRegistry;
use peat_gateway::config::{CdcConfig, GatewayConfig, MeshBrokerMapping, StorageConfig};
use peat_gateway::mesh_ingest::MeshIngestManager;
use peat_gateway::tenant::models::EnrollmentPolicy;
use peat_gateway::tenant::TenantManager;
use reqwest::Client;
use serde_json::{json, Value};

#[derive(Clone)]
struct FakeBrokerState {
    node: Value,
    topology: Value,
    ready: Value,
    peers: Value,
    contacts: Value,
    markers: Value,
}

async fn fake_node(State(state): State<FakeBrokerState>) -> Json<Value> {
    Json(state.node)
}

async fn fake_topology(State(state): State<FakeBrokerState>) -> Json<Value> {
    Json(state.topology)
}

async fn fake_ready(State(state): State<FakeBrokerState>) -> Json<Value> {
    Json(state.ready)
}

async fn fake_peers(State(state): State<FakeBrokerState>) -> Json<Value> {
    Json(state.peers)
}

async fn fake_documents(
    State(state): State<FakeBrokerState>,
    axum::extract::Path(collection): axum::extract::Path<String>,
) -> Result<Json<Value>, axum::http::StatusCode> {
    match collection.as_str() {
        "contacts" => Ok(Json(state.contacts)),
        "markers" => Ok(Json(state.markers)),
        _ => Err(axum::http::StatusCode::NOT_FOUND),
    }
}

async fn spawn_fake_broker() -> (String, tokio::task::JoinHandle<()>) {
    let state = FakeBrokerState {
        node: json!({
            "node_id": "fake-broker-node",
            "uptime_secs": 12,
            "version": "0.5.2"
        }),
        topology: json!({
            "peer_count": 1,
            "role": "standalone",
            "hierarchy_level": 0
        }),
        ready: json!({
            "ready": true,
            "node_id": "fake-broker-node",
            "checks": [{"name": "remote-broker", "ready": true, "message": "ok"}]
        }),
        peers: json!({
            "peers": [{
                "id": "peer-ios-1",
                "connected": true,
                "state": "connected",
                "rtt_ms": 7
            }],
            "count": 1
        }),
        contacts: json!({
            "collection": "contacts",
            "count": 1,
            "documents": [{
                "_id": "contact-1",
                "uid": "contact-1",
                "callsign": "Alpha",
                "lat": 52.1,
                "lon": 21.0
            }]
        }),
        markers: json!({
            "collection": "markers",
            "count": 1,
            "documents": [{
                "_id": "marker-1",
                "uid": "marker-1",
                "type": "b-m-p-s-p-loc",
                "lat": 52.2,
                "lon": 21.1
            }]
        }),
    };

    let app = Router::new()
        .route("/api/v1/node", get(fake_node))
        .route("/api/v1/topology", get(fake_topology))
        .route("/api/v1/ready", get(fake_ready))
        .route("/api/v1/peers", get(fake_peers))
        .route("/api/v1/documents/:collection", get(fake_documents))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{}", addr);
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base, handle)
}

async fn spawn_gateway_with_remote_broker(
    broker_url: &str,
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
        kek: None,
        kms_key_arn: None,
        admin_token: None,
        vault_addr: None,
        vault_token: None,
        vault_transit_key: None,
        mesh_brokers: vec![],
        mesh_poll_interval_ms: 25,
    };

    let tenant_mgr = TenantManager::new(&config).await.unwrap();
    let registry = MeshStateRegistry::new();
    let manager = MeshIngestManager::new(registry.clone(), std::time::Duration::from_millis(25));
    manager
        .register_remote_broker(MeshBrokerMapping {
            org_id: "acme".into(),
            app_id: "myapp".into(),
            base_url: broker_url.into(),
            collections: vec!["contacts".into(), "markers".into()],
        })
        .await;

    let app = api::app_authenticated_with_mesh(tenant_mgr.clone(), None, registry);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = Client::new();
    (client, format!("http://{}", addr), dir, tenant_mgr)
}

#[tokio::test]
async fn gateway_surfaces_remote_broker_peers_and_documents() {
    let (broker_url, _broker_task) = spawn_fake_broker().await;
    let (client, base, _dir, mgr) = spawn_gateway_with_remote_broker(&broker_url).await;

    mgr.create_org("acme".into(), "Acme".into()).await.unwrap();
    mgr.create_formation("acme", "myapp".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let peers_resp = client
        .get(format!("{base}/orgs/acme/formations/myapp/peers"))
        .send()
        .await
        .unwrap();
    assert!(peers_resp.status().is_success());
    let peers: Vec<Value> = peers_resp.json().await.unwrap();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0]["peer_id"], "peer-ios-1");
    assert_eq!(peers[0]["status"], "Connected");

    let docs_resp = client
        .get(format!("{base}/orgs/acme/formations/myapp/documents"))
        .send()
        .await
        .unwrap();
    assert!(docs_resp.status().is_success());
    let docs: Vec<Value> = docs_resp.json().await.unwrap();
    assert_eq!(docs.len(), 2);
    let ids: Vec<String> = docs
        .iter()
        .filter_map(|doc| doc["doc_id"].as_str().map(ToOwned::to_owned))
        .collect();
    assert!(ids.contains(&"contact-1".to_string()));
    assert!(ids.contains(&"marker-1".to_string()));
}
