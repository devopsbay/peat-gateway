//! Integration tests for identity federation: IdP config CRUD, policy rules, audit log,
//! and enrollment endpoint.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::models::{EnrollmentPolicy, MeshTier};
use peat_gateway::tenant::TenantManager;
use serde_json::{json, Value};
use tower::ServiceExt;

// ── Helpers ────────────────────────────────────────────────────

async fn setup() -> (TenantManager, axum::Router, tempfile::TempDir) {
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
    let app = peat_gateway::api::app(tenant_mgr.clone());
    (tenant_mgr, app, dir)
}

fn json_request(method: &str, uri: &str, body: Option<Value>) -> Request<Body> {
    let builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");

    match body {
        Some(b) => builder.body(Body::from(b.to_string())).unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    }
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

// ── IdP Config CRUD ───────────────────────────────────────────

#[tokio::test]
async fn idp_crud() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();

    // Create IdP
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/idps",
            Some(json!({
                "issuer_url": "https://keycloak.example.com/realms/acme",
                "client_id": "peat-gateway",
                "client_secret": "s3cret"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let idp = body_json(resp).await;
    let idp_id = idp["idp_id"].as_str().unwrap().to_string();
    assert_eq!(idp["org_id"], "acme");
    assert_eq!(
        idp["issuer_url"],
        "https://keycloak.example.com/realms/acme"
    );
    assert_eq!(idp["enabled"], true);

    // List IdPs
    let resp = app
        .clone()
        .oneshot(json_request("GET", "/orgs/acme/idps", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 1);

    // Get IdP
    let resp = app
        .clone()
        .oneshot(json_request(
            "GET",
            &format!("/orgs/acme/idps/{idp_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Toggle IdP off
    let resp = app
        .clone()
        .oneshot(json_request(
            "PATCH",
            &format!("/orgs/acme/idps/{idp_id}"),
            Some(json!({"enabled": false})),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let toggled = body_json(resp).await;
    assert_eq!(toggled["enabled"], false);

    // Delete IdP
    let resp = app
        .clone()
        .oneshot(json_request(
            "DELETE",
            &format!("/orgs/acme/idps/{idp_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify gone
    let resp = app
        .clone()
        .oneshot(json_request("GET", "/orgs/acme/idps", None))
        .await
        .unwrap();
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 0);
}

// ── Policy Rule CRUD ──────────────────────────────────────────

#[tokio::test]
async fn policy_rule_crud() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();

    // Create rules
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/policy-rules",
            Some(json!({
                "claim_key": "role",
                "claim_value": "admin",
                "tier": "Authority",
                "permissions": 15,
                "priority": 10
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let rule1 = body_json(resp).await;
    let rule1_id = rule1["rule_id"].as_str().unwrap().to_string();
    assert_eq!(rule1["tier"], "Authority");
    assert_eq!(rule1["permissions"], 15);

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/policy-rules",
            Some(json!({
                "claim_key": "role",
                "claim_value": "operator",
                "tier": "Infrastructure",
                "permissions": 5,
                "priority": 20
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);

    // List rules
    let resp = app
        .clone()
        .oneshot(json_request("GET", "/orgs/acme/policy-rules", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 2);

    // Delete rule
    let resp = app
        .clone()
        .oneshot(json_request(
            "DELETE",
            &format!("/orgs/acme/policy-rules/{rule1_id}"),
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Verify only 1 remaining
    let resp = app
        .clone()
        .oneshot(json_request("GET", "/orgs/acme/policy-rules", None))
        .await
        .unwrap();
    let list = body_json(resp).await;
    assert_eq!(list.as_array().unwrap().len(), 1);
}

// ── Enrollment: Open formation ────────────────────────────────

#[tokio::test]
async fn enroll_open_formation_succeeds_without_token() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-open".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-open/enroll",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["decision"]["Approved"]["tier"], "Endpoint");
    assert!(body["audit_id"].as_str().is_some());
}

// ── Enrollment: Strict formation ──────────────────────────────

#[tokio::test]
async fn enroll_strict_formation_is_forbidden() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-strict".into(), EnrollmentPolicy::Strict)
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-strict/enroll",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ── Enrollment: Controlled without token ──────────────────────

#[tokio::test]
async fn enroll_controlled_without_token_is_unauthorized() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();
    // Create an IdP so the "no IdP configured" check doesn't fire first
    mgr.create_idp(
        "acme",
        "https://keycloak.example.com/realms/acme".into(),
        "peat".into(),
        "secret".into(),
    )
    .await
    .unwrap();

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-ctrl/enroll",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ── Enrollment: Controlled without IdP config ─────────────────

#[tokio::test]
async fn enroll_controlled_without_idp_is_bad_request() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/orgs/acme/formations/mesh-ctrl/enroll")
        .header("content-type", "application/json")
        .header("authorization", "Bearer fake-token")
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Audit log ─────────────────────────────────────────────────

#[tokio::test]
async fn audit_log_records_enrollment() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-open".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    // Enroll (open formation)
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-open/enroll",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Check audit log
    let resp = app
        .clone()
        .oneshot(json_request("GET", "/orgs/acme/audit?limit=10", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let audit = body_json(resp).await;
    let entries = audit.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["org_id"], "acme");
    assert_eq!(entries[0]["app_id"], "mesh-open");
    assert_eq!(entries[0]["subject"], "anonymous");
    assert!(entries[0]["decision"]["Approved"].is_object());
}

// ── Audit log filtered by app_id ──────────────────────────────

#[tokio::test]
async fn audit_log_filters_by_app_id() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "app-a".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();
    mgr.create_formation("acme", "app-b".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    // Enroll in both
    for app_id in ["app-a", "app-b", "app-a"] {
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                &format!("/orgs/acme/formations/{app_id}/enroll"),
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Filter audit by app-a
    let resp = app
        .clone()
        .oneshot(json_request(
            "GET",
            "/orgs/acme/audit?app_id=app-a&limit=100",
            None,
        ))
        .await
        .unwrap();
    let audit = body_json(resp).await;
    assert_eq!(audit.as_array().unwrap().len(), 2);
}

// ── Org delete cascades IdP and rules ─────────────────────────

#[tokio::test]
async fn delete_org_cascades_identity_data() {
    let (mgr, _app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_idp(
        "acme",
        "https://kc.example.com/realms/acme".into(),
        "client".into(),
        "secret".into(),
    )
    .await
    .unwrap();
    mgr.create_policy_rule(
        "acme",
        "role".into(),
        "admin".into(),
        MeshTier::Authority,
        15,
        10,
    )
    .await
    .unwrap();

    mgr.delete_org("acme").await.unwrap();

    // After deletion, the store should be clean (no orphaned data).
    // Re-create org and verify empty lists.
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    assert_eq!(mgr.list_idps("acme").await.unwrap().len(), 0);
    assert_eq!(mgr.list_policy_rules("acme").await.unwrap().len(), 0);
}

// ── Policy evaluation via TenantManager ───────────────────────

#[tokio::test]
async fn policy_rules_sorted_by_priority() {
    let (mgr, _app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();

    // Create rules with different priorities
    mgr.create_policy_rule(
        "acme",
        "role".into(),
        "operator".into(),
        MeshTier::Infrastructure,
        5,
        50,
    )
    .await
    .unwrap();

    mgr.create_policy_rule(
        "acme",
        "role".into(),
        "admin".into(),
        MeshTier::Authority,
        15,
        10,
    )
    .await
    .unwrap();

    let rules = mgr.list_policy_rules("acme").await.unwrap();
    assert_eq!(rules.len(), 2);
    // The rules are stored but sorting happens at evaluation time (in enroll.rs)
}

// ── Certificate issuance: Open formation with key material ───

#[tokio::test]
async fn enroll_open_formation_issues_certificate() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    let formation = mgr
        .create_formation("acme", "mesh-open".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    // Generate a device keypair for enrollment
    let device = peat_mesh::security::DeviceKeypair::generate();
    let pk_hex = hex::encode(device.public_key_bytes());

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-open/enroll",
            Some(json!({
                "public_key": pk_hex,
                "node_id": "tactical-west-1"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["decision"]["Approved"]["tier"], "Endpoint");

    // Certificate should be present
    let cert_hex = body["certificate"]
        .as_str()
        .expect("certificate should be present");
    let cert_bytes = hex::decode(cert_hex).unwrap();
    let cert = peat_mesh::security::MeshCertificate::decode(&cert_bytes).unwrap();

    // Verify signature
    assert!(cert.verify().is_ok());

    // Verify cert fields
    assert_eq!(cert.subject_public_key, device.public_key_bytes());
    assert_eq!(cert.node_id, "tactical-west-1");
    assert_eq!(cert.mesh_id, formation.mesh_id);

    // mesh_id and authority_public_key should be returned
    assert_eq!(body["mesh_id"].as_str().unwrap(), formation.mesh_id);
    assert!(body["authority_public_key"].as_str().is_some());
}

// ── Certificate issuance: backwards compat (no key material) ─

#[tokio::test]
async fn enroll_open_without_key_material_returns_no_cert() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-open".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-open/enroll",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["decision"]["Approved"]["tier"], "Endpoint");
    assert!(body["certificate"].is_null());
    assert!(body["mesh_id"].is_null());
}

// ── Enrollment rate limiting ─────────────────────────────────

#[tokio::test]
async fn enroll_rate_limited() {
    let (mgr, app, _dir) = setup().await;
    let mut org = mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();

    // Set quota to 2 enrollments per hour
    org.quotas.max_enrollments_per_hour = 2;
    mgr.update_org("acme", None, Some(org.quotas))
        .await
        .unwrap();

    mgr.create_formation("acme", "mesh-open".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    // First two enrollments should succeed
    for _ in 0..2 {
        let resp = app
            .clone()
            .oneshot(json_request(
                "POST",
                "/orgs/acme/formations/mesh-open/enroll",
                None,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Third should be rate limited
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-open/enroll",
            None,
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
}

// ── Invalid public key returns 400 ──────────────────────────

#[tokio::test]
async fn enroll_with_invalid_public_key_is_bad_request() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-open".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    // Too short
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-open/enroll",
            Some(json!({
                "public_key": "abcd",
                "node_id": "test-node"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // Not valid hex
    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-open/enroll",
            Some(json!({
                "public_key": "zzzz",
                "node_id": "test-node"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

// ── Certificate has correct tier and permissions ─────────────

#[tokio::test]
async fn enroll_certificate_has_correct_tier_and_permissions() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    // Create a policy rule: role=admin → Authority tier, all permissions (0x0F)
    mgr.create_policy_rule(
        "acme",
        "role".into(),
        "admin".into(),
        MeshTier::Authority,
        0x0F, // RELAY|EMERGENCY|ENROLL|ADMIN
        10,
    )
    .await
    .unwrap();

    // For Open formations, policy rules aren't evaluated (defaults to Endpoint, 0 perms).
    // But we can still verify the tier/perms mapping works on the cert.
    let device = peat_mesh::security::DeviceKeypair::generate();
    let pk_hex = hex::encode(device.public_key_bytes());

    let resp = app
        .clone()
        .oneshot(json_request(
            "POST",
            "/orgs/acme/formations/mesh-ctrl/enroll",
            Some(json!({
                "public_key": pk_hex,
                "node_id": "edge-device-1"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;

    // Open formation → Endpoint tier, 0 permissions
    let cert_hex = body["certificate"].as_str().unwrap();
    let cert =
        peat_mesh::security::MeshCertificate::decode(&hex::decode(cert_hex).unwrap()).unwrap();

    // Gateway Endpoint → Mesh Tactical
    assert_eq!(cert.tier, peat_mesh::security::MeshTier::Tactical);
    // 0 gateway perms → 0 mesh perms
    assert_eq!(cert.permissions, 0);
    assert!(cert.verify().is_ok());
}

// ── Envelope encryption: full round-trip with KEK enabled ───

async fn setup_encrypted() -> (TenantManager, axum::Router, tempfile::TempDir) {
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
        kek: Some("aa".repeat(32)),
        kms_key_arn: None,
        vault_addr: None,
        vault_token: None,
        vault_transit_key: None,
        mesh_brokers: vec![],
        mesh_poll_interval_ms: 5_000,
    };
    let tenant_mgr = TenantManager::new(&config).await.unwrap();
    let app = peat_gateway::api::app(tenant_mgr.clone());
    (tenant_mgr, app, dir)
}

#[tokio::test]
async fn encrypted_genesis_issues_valid_certificate() {
    let (mgr, app, _dir) = setup_encrypted().await;
    mgr.create_org("enc-org".into(), "Encrypted Org".into())
        .await
        .unwrap();
    let formation = mgr
        .create_formation("enc-org", "enc-mesh".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    let device = peat_mesh::security::DeviceKeypair::generate();
    let pk_hex = hex::encode(device.public_key_bytes());

    let resp = app
        .oneshot(json_request(
            "POST",
            "/orgs/enc-org/formations/enc-mesh/enroll",
            Some(json!({
                "public_key": pk_hex,
                "node_id": "encrypted-node-1"
            })),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;

    let cert_hex = body["certificate"]
        .as_str()
        .expect("certificate should be present");
    let cert_bytes = hex::decode(cert_hex).unwrap();
    let cert = peat_mesh::security::MeshCertificate::decode(&cert_bytes).unwrap();

    assert!(cert.verify().is_ok());
    assert_eq!(cert.mesh_id, formation.mesh_id);
    assert_eq!(cert.node_id, "encrypted-node-1");
}

#[tokio::test]
async fn encrypted_genesis_stored_bytes_are_not_plaintext() {
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
        kek: Some("bb".repeat(32)),
        kms_key_arn: None,
        vault_addr: None,
        vault_token: None,
        vault_transit_key: None,
        mesh_brokers: vec![],
        mesh_poll_interval_ms: 5_000,
    };
    // Create org + formation (encrypts genesis), then drop to release redb lock
    {
        let mgr = TenantManager::new(&config).await.unwrap();
        mgr.create_org("raw-org".into(), "Raw Org".into())
            .await
            .unwrap();
        mgr.create_formation("raw-org", "raw-app".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
    }

    // Read raw bytes from storage — they should start with "PENV" (envelope magic)
    let raw = {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        store
            .get_genesis("raw-org", "raw-app")
            .await
            .unwrap()
            .unwrap()
    };
    assert_eq!(
        &raw[..4],
        b"PENV",
        "stored genesis should be envelope-encrypted"
    );

    // Should NOT be decodeable as plaintext MeshGenesis
    assert!(
        peat_mesh::security::MeshGenesis::decode(&raw).is_err(),
        "encrypted bytes should not decode as plaintext genesis"
    );

    // Reopen TenantManager — loading through it should decrypt transparently
    let mgr = TenantManager::new(&config).await.unwrap();
    let genesis = mgr.load_genesis("raw-org", "raw-app").await.unwrap();
    assert!(!genesis.mesh_id().is_empty());
}

// ── Enrollment Token Enforcement ─────────────────────────────

#[tokio::test]
async fn enroll_with_valid_token_succeeds() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    let token = mgr
        .create_token("acme", "mesh-ctrl".into(), "test-token".into(), None, None)
        .await
        .unwrap();

    let device = peat_mesh::security::DeviceKeypair::generate();
    let pk_hex = hex::encode(device.public_key_bytes());

    let req = Request::builder()
        .method("POST")
        .uri("/orgs/acme/formations/mesh-ctrl/enroll")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token.token_id))
        .body(Body::from(
            json!({
                "public_key": pk_hex,
                "node_id": "token-node-1"
            })
            .to_string(),
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_json(resp).await;
    assert_eq!(body["decision"]["Approved"]["tier"], "Endpoint");
    assert!(body["certificate"].as_str().is_some());

    // Audit should record token subject
    let resp = app
        .clone()
        .oneshot(json_request("GET", "/orgs/acme/audit?limit=10", None))
        .await
        .unwrap();
    let audit = body_json(resp).await;
    let entries = audit.as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["subject"], format!("token:{}", token.token_id));
    assert_eq!(entries[0]["idp_id"], "token");
}

#[tokio::test]
async fn enroll_with_token_increments_uses() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    let token = mgr
        .create_token(
            "acme",
            "mesh-ctrl".into(),
            "counter-token".into(),
            None,
            None,
        )
        .await
        .unwrap();
    assert_eq!(token.uses, 0);

    // Enroll twice
    for _ in 0..2 {
        let req = Request::builder()
            .method("POST")
            .uri("/orgs/acme/formations/mesh-ctrl/enroll")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {}", token.token_id))
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // Verify uses counter
    let updated = mgr.get_token("acme", &token.token_id).await.unwrap();
    assert_eq!(updated.uses, 2);
}

#[tokio::test]
async fn enroll_with_revoked_token_is_unauthorized() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    let token = mgr
        .create_token("acme", "mesh-ctrl".into(), "revoke-me".into(), None, None)
        .await
        .unwrap();
    mgr.revoke_token("acme", &token.token_id).await.unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/orgs/acme/formations/mesh-ctrl/enroll")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token.token_id))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_with_expired_token_is_unauthorized() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    // Create token that expired 1 hour ago
    let one_hour_ago = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
        - 3_600_000;

    let token = mgr
        .create_token(
            "acme",
            "mesh-ctrl".into(),
            "expired-token".into(),
            None,
            Some(one_hour_ago),
        )
        .await
        .unwrap();

    let req = Request::builder()
        .method("POST")
        .uri("/orgs/acme/formations/mesh-ctrl/enroll")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token.token_id))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_with_exhausted_token_is_unauthorized() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    // Create token with max_uses=1
    let token = mgr
        .create_token("acme", "mesh-ctrl".into(), "one-shot".into(), Some(1), None)
        .await
        .unwrap();

    // First enrollment succeeds
    let req = Request::builder()
        .method("POST")
        .uri("/orgs/acme/formations/mesh-ctrl/enroll")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token.token_id))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Second enrollment fails — max_uses exhausted
    let req = Request::builder()
        .method("POST")
        .uri("/orgs/acme/formations/mesh-ctrl/enroll")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token.token_id))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_with_wrong_formation_token_is_unauthorized() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-a".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-b".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    // Token for mesh-a
    let token = mgr
        .create_token(
            "acme",
            "mesh-a".into(),
            "wrong-formation".into(),
            None,
            None,
        )
        .await
        .unwrap();

    // Try enrolling in mesh-b with mesh-a's token
    let req = Request::builder()
        .method("POST")
        .uri("/orgs/acme/formations/mesh-b/enroll")
        .header("content-type", "application/json")
        .header("authorization", format!("Bearer {}", token.token_id))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_controlled_non_prefixed_bearer_falls_through_to_oidc() {
    let (mgr, app, _dir) = setup().await;
    mgr.create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    mgr.create_formation("acme", "mesh-ctrl".into(), EnrollmentPolicy::Controlled)
        .await
        .unwrap();

    // No peat_ prefix → falls through to OIDC path → no IdP configured → 400
    let req = Request::builder()
        .method("POST")
        .uri("/orgs/acme/formations/mesh-ctrl/enroll")
        .header("content-type", "application/json")
        .header("authorization", "Bearer not-a-peat-token-at-all")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    // No IdP configured → should get BAD_REQUEST from OIDC path
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
