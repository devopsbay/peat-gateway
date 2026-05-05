//! Integration tests for the Postgres storage backend.
//!
//! Requires a running Postgres server. Set `PEAT_TEST_POSTGRES_URL` or defaults
//! to `postgres://peat:peat@localhost:5432/postgres`. Skipped automatically if
//! Postgres is unreachable.
//!
//! Each test creates a unique database and drops it on completion for full
//! isolation. Tests can run in parallel safely.

#![cfg(feature = "postgres")]

use std::time::Duration;

use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::storage::{self, StorageBackend};
use peat_gateway::tenant::models::*;
use peat_gateway::tenant::TenantManager;
use sqlx::PgPool;

fn admin_url() -> String {
    std::env::var("PEAT_TEST_POSTGRES_URL")
        .unwrap_or_else(|_| "postgres://peat:peat@localhost:5432/postgres".into())
}

/// Create a unique test database, returning its URL and name.
/// Returns None if Postgres is unreachable.
async fn create_test_db(test_name: &str) -> Option<(String, String)> {
    let url = admin_url();
    let pool = match tokio::time::timeout(Duration::from_secs(3), PgPool::connect(&url)).await {
        Ok(Ok(pool)) => pool,
        _ => {
            eprintln!("Postgres not available at {url}, skipping postgres tests");
            return None;
        }
    };

    // Unique DB name per test to allow parallel execution
    let db_name = format!("peat_test_{}", test_name);

    // Drop if leftover from a previous failed run
    sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
        .execute(&pool)
        .await
        .ok()?;
    sqlx::query(&format!("CREATE DATABASE \"{db_name}\""))
        .execute(&pool)
        .await
        .ok()?;

    // Build the test URL pointing at the new database
    let base = url.rsplit_once('/').map(|(base, _)| base).unwrap_or(&url);
    let test_url = format!("{base}/{db_name}");

    pool.close().await;
    Some((test_url, db_name))
}

/// Drop a test database. Best-effort cleanup.
async fn drop_test_db(db_name: &str) {
    let url = admin_url();
    if let Ok(pool) = PgPool::connect(&url).await {
        // Terminate active connections first
        let _ = sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1",
        )
        .bind(db_name)
        .execute(&pool)
        .await;
        let _ = sqlx::query(&format!("DROP DATABASE IF EXISTS \"{db_name}\""))
            .execute(&pool)
            .await;
        pool.close().await;
    }
}

async fn open_store(url: &str) -> Box<dyn StorageBackend> {
    storage::open(&StorageConfig::Postgres { url: url.into() })
        .await
        .unwrap()
}

fn make_config(url: &str, kek: Option<&str>) -> GatewayConfig {
    GatewayConfig {
        bind_addr: "127.0.0.1:0".into(),
        storage: StorageConfig::Postgres { url: url.into() },
        cdc: CdcConfig {
            nats_url: None,
            kafka_brokers: None,
        },
        ui_dir: None,
        admin_token: None,
        kek: kek.map(String::from),
        kms_key_arn: None,
        vault_addr: None,
        vault_token: None,
        vault_transit_key: None,
        mesh_brokers: vec![],
        mesh_poll_interval_ms: 5_000,
    }
}

fn sample_org(id: &str) -> Organization {
    Organization {
        org_id: id.into(),
        display_name: format!("{id} Corp"),
        quotas: OrgQuotas::default(),
        created_at: 1700000000000,
    }
}

// ── Org CRUD ──────────────────────────────────────────────────

#[tokio::test]
async fn pg_org_crud() {
    let Some((url, db)) = create_test_db("org_crud").await else {
        return;
    };
    let store = open_store(&url).await;

    // Empty initially
    assert!(store.list_orgs().await.unwrap().is_empty());

    // Create
    let org = sample_org("acme");
    store.create_org(&org).await.unwrap();

    // Get
    let fetched = store.get_org("acme").await.unwrap().unwrap();
    assert_eq!(fetched.org_id, "acme");
    assert_eq!(fetched.display_name, "acme Corp");

    // List
    let orgs = store.list_orgs().await.unwrap();
    assert_eq!(orgs.len(), 1);

    // Update
    let mut updated = fetched;
    updated.display_name = "Acme Industries".into();
    store.update_org(&updated).await.unwrap();
    let re_fetched = store.get_org("acme").await.unwrap().unwrap();
    assert_eq!(re_fetched.display_name, "Acme Industries");

    // Delete
    assert!(store.delete_org("acme").await.unwrap());
    assert!(store.get_org("acme").await.unwrap().is_none());
    assert!(!store.delete_org("acme").await.unwrap()); // idempotent

    drop_test_db(&db).await;
}

// ── Formation CRUD ────────────────────────────────────────────

#[tokio::test]
async fn pg_formation_crud() {
    let Some((url, db)) = create_test_db("formation_crud").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("acme")).await.unwrap();

    let formation = FormationConfig {
        app_id: "mesh-1".into(),
        mesh_id: "deadbeef".into(),
        enrollment_policy: EnrollmentPolicy::Open,
    };
    store.create_formation("acme", &formation).await.unwrap();

    let fetched = store
        .get_formation("acme", "mesh-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched.mesh_id, "deadbeef");

    let list = store.list_formations("acme").await.unwrap();
    assert_eq!(list.len(), 1);

    assert!(store.delete_formation("acme", "mesh-1").await.unwrap());
    assert!(store
        .get_formation("acme", "mesh-1")
        .await
        .unwrap()
        .is_none());

    drop_test_db(&db).await;
}

// ── Delete org cascades ───────────────────────────────────────

#[tokio::test]
async fn pg_delete_org_cascades() {
    let Some((url, db)) = create_test_db("delete_cascade").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("cascade")).await.unwrap();
    store
        .create_formation(
            "cascade",
            &FormationConfig {
                app_id: "app-1".into(),
                mesh_id: "aabb".into(),
                enrollment_policy: EnrollmentPolicy::Controlled,
            },
        )
        .await
        .unwrap();
    store
        .store_genesis("cascade", "app-1", b"fake-genesis")
        .await
        .unwrap();
    store
        .create_token(&EnrollmentToken {
            token_id: "tok-1".into(),
            org_id: "cascade".into(),
            app_id: "app-1".into(),
            label: "test".into(),
            max_uses: None,
            uses: 0,
            expires_at: None,
            created_at: 1700000000000,
            revoked: false,
        })
        .await
        .unwrap();
    store
        .create_sink(&CdcSinkConfig {
            sink_id: "sink-1".into(),
            org_id: "cascade".into(),
            sink_type: CdcSinkType::Webhook {
                url: "http://example.com".into(),
            },
            enabled: true,
            created_at: 1700000000000,
        })
        .await
        .unwrap();
    store
        .create_idp(&IdpConfig {
            idp_id: "idp-1".into(),
            org_id: "cascade".into(),
            issuer_url: "https://example.com".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            enabled: true,
            created_at: 1700000000000,
        })
        .await
        .unwrap();
    store
        .create_policy_rule(&PolicyRule {
            rule_id: "rule-1".into(),
            org_id: "cascade".into(),
            claim_key: "role".into(),
            claim_value: "admin".into(),
            tier: MeshTier::Authority,
            permissions: 0x0F,
            priority: 10,
        })
        .await
        .unwrap();
    store
        .append_audit(&EnrollmentAuditEntry {
            audit_id: "audit-1".into(),
            org_id: "cascade".into(),
            app_id: "app-1".into(),
            idp_id: "idp-1".into(),
            subject: "user@example.com".into(),
            decision: EnrollmentDecision::Approved {
                tier: MeshTier::Endpoint,
                permissions: 0x01,
            },
            timestamp_ms: 1700000000000,
        })
        .await
        .unwrap();
    store
        .set_cursor("cascade", "app-1", "doc-1", "hash-abc")
        .await
        .unwrap();

    // Delete org — everything should cascade
    assert!(store.delete_org("cascade").await.unwrap());
    assert!(store.list_formations("cascade").await.unwrap().is_empty());
    assert!(store
        .get_genesis("cascade", "app-1")
        .await
        .unwrap()
        .is_none());
    assert!(store.get_token("cascade", "tok-1").await.unwrap().is_none());
    assert!(store.list_sinks("cascade").await.unwrap().is_empty());
    assert!(store.list_idps("cascade").await.unwrap().is_empty());
    assert!(store.list_policy_rules("cascade").await.unwrap().is_empty());
    assert!(store
        .list_audit("cascade", None, 100)
        .await
        .unwrap()
        .is_empty());
    assert!(store
        .get_cursor("cascade", "app-1", "doc-1")
        .await
        .unwrap()
        .is_none());

    drop_test_db(&db).await;
}

// ── Enrollment tokens ─────────────────────────────────────────

#[tokio::test]
async fn pg_token_crud() {
    let Some((url, db)) = create_test_db("token_crud").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("acme")).await.unwrap();

    let token = EnrollmentToken {
        token_id: "tok-abc".into(),
        org_id: "acme".into(),
        app_id: "mesh-1".into(),
        label: "CI token".into(),
        max_uses: Some(10),
        uses: 0,
        expires_at: Some(1800000000000),
        created_at: 1700000000000,
        revoked: false,
    };
    store.create_token(&token).await.unwrap();

    let fetched = store.get_token("acme", "tok-abc").await.unwrap().unwrap();
    assert_eq!(fetched.label, "CI token");
    assert_eq!(fetched.max_uses, Some(10));

    // Update (revoke)
    let mut revoked = fetched;
    revoked.revoked = true;
    revoked.uses = 3;
    store.update_token(&revoked).await.unwrap();
    let re = store.get_token("acme", "tok-abc").await.unwrap().unwrap();
    assert!(re.revoked);
    assert_eq!(re.uses, 3);

    // List filtered by app_id
    let list = store.list_tokens("acme", "mesh-1").await.unwrap();
    assert_eq!(list.len(), 1);
    let list_other = store.list_tokens("acme", "other-app").await.unwrap();
    assert!(list_other.is_empty());

    // Delete
    assert!(store.delete_token("acme", "tok-abc").await.unwrap());
    assert!(store.get_token("acme", "tok-abc").await.unwrap().is_none());

    drop_test_db(&db).await;
}

// ── CDC sinks ─────────────────────────────────────────────────

#[tokio::test]
async fn pg_sink_crud() {
    let Some((url, db)) = create_test_db("sink_crud").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("acme")).await.unwrap();

    let sink = CdcSinkConfig {
        sink_id: "sink-1".into(),
        org_id: "acme".into(),
        sink_type: CdcSinkType::Nats {
            subject_prefix: "peat.acme".into(),
        },
        enabled: true,
        created_at: 1700000000000,
    };
    store.create_sink(&sink).await.unwrap();

    let fetched = store.get_sink("acme", "sink-1").await.unwrap().unwrap();
    assert!(fetched.enabled);

    // Toggle
    let mut disabled = fetched;
    disabled.enabled = false;
    store.update_sink(&disabled).await.unwrap();
    let re = store.get_sink("acme", "sink-1").await.unwrap().unwrap();
    assert!(!re.enabled);

    let list = store.list_sinks("acme").await.unwrap();
    assert_eq!(list.len(), 1);

    assert!(store.delete_sink("acme", "sink-1").await.unwrap());

    drop_test_db(&db).await;
}

// ── IdP configs ───────────────────────────────────────────────

#[tokio::test]
async fn pg_idp_crud() {
    let Some((url, db)) = create_test_db("idp_crud").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("acme")).await.unwrap();

    let idp = IdpConfig {
        idp_id: "idp-1".into(),
        org_id: "acme".into(),
        issuer_url: "https://keycloak.example.com/realms/peat".into(),
        client_id: "peat-gw".into(),
        client_secret: "super-secret".into(),
        enabled: true,
        created_at: 1700000000000,
    };
    store.create_idp(&idp).await.unwrap();

    let fetched = store.get_idp("acme", "idp-1").await.unwrap().unwrap();
    assert_eq!(
        fetched.issuer_url,
        "https://keycloak.example.com/realms/peat"
    );

    // Toggle
    let mut toggled = fetched;
    toggled.enabled = false;
    store.update_idp(&toggled).await.unwrap();
    assert!(
        !store
            .get_idp("acme", "idp-1")
            .await
            .unwrap()
            .unwrap()
            .enabled
    );

    let list = store.list_idps("acme").await.unwrap();
    assert_eq!(list.len(), 1);

    assert!(store.delete_idp("acme", "idp-1").await.unwrap());

    drop_test_db(&db).await;
}

// ── Policy rules ──────────────────────────────────────────────

#[tokio::test]
async fn pg_policy_rules() {
    let Some((url, db)) = create_test_db("policy_rules").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("acme")).await.unwrap();

    let rule = PolicyRule {
        rule_id: "rule-1".into(),
        org_id: "acme".into(),
        claim_key: "role".into(),
        claim_value: "admin".into(),
        tier: MeshTier::Authority,
        permissions: 0x0F,
        priority: 10,
    };
    store.create_policy_rule(&rule).await.unwrap();

    let list = store.list_policy_rules("acme").await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].claim_key, "role");

    assert!(store.delete_policy_rule("acme", "rule-1").await.unwrap());
    assert!(store.list_policy_rules("acme").await.unwrap().is_empty());

    drop_test_db(&db).await;
}

// ── Audit log ─────────────────────────────────────────────────

#[tokio::test]
async fn pg_audit_log() {
    let Some((url, db)) = create_test_db("audit_log").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("acme")).await.unwrap();

    for i in 0..3 {
        store
            .append_audit(&EnrollmentAuditEntry {
                audit_id: format!("audit-{i}"),
                org_id: "acme".into(),
                app_id: if i < 2 { "mesh-1" } else { "mesh-2" }.into(),
                idp_id: "idp-1".into(),
                subject: format!("user-{i}@example.com"),
                decision: EnrollmentDecision::Approved {
                    tier: MeshTier::Endpoint,
                    permissions: 0x01,
                },
                timestamp_ms: 1700000000000 + i as u64,
            })
            .await
            .unwrap();
    }

    // Add a Denied entry to verify enum variant roundtrips
    store
        .append_audit(&EnrollmentAuditEntry {
            audit_id: "audit-denied".into(),
            org_id: "acme".into(),
            app_id: "mesh-1".into(),
            idp_id: "idp-1".into(),
            subject: "blocked@example.com".into(),
            decision: EnrollmentDecision::Denied {
                reason: "insufficient claims".into(),
            },
            timestamp_ms: 1700000000001,
        })
        .await
        .unwrap();

    // List all
    let all = store.list_audit("acme", None, 100).await.unwrap();
    assert_eq!(all.len(), 4);

    // Filter by app_id
    let filtered = store.list_audit("acme", Some("mesh-1"), 100).await.unwrap();
    assert_eq!(filtered.len(), 3);

    // Verify Denied variant roundtripped correctly
    let denied = filtered
        .iter()
        .find(|e| e.audit_id == "audit-denied")
        .expect("denied entry should exist");
    match &denied.decision {
        EnrollmentDecision::Denied { reason } => {
            assert_eq!(reason, "insufficient claims");
        }
        other => panic!("expected Denied, got {other:?}"),
    }

    // Limit
    let limited = store.list_audit("acme", None, 2).await.unwrap();
    assert_eq!(limited.len(), 2);

    drop_test_db(&db).await;
}

// ── Genesis key material ──────────────────────────────────────

#[tokio::test]
async fn pg_genesis_store_and_retrieve() {
    let Some((url, db)) = create_test_db("genesis_basic").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("acme")).await.unwrap();

    let data = b"fake-genesis-key-material-32bytes";
    store.store_genesis("acme", "mesh-1", data).await.unwrap();

    let fetched = store.get_genesis("acme", "mesh-1").await.unwrap().unwrap();
    assert_eq!(fetched, data);

    // Overwrite (upsert)
    let updated = b"new-genesis-material";
    store
        .store_genesis("acme", "mesh-1", updated)
        .await
        .unwrap();
    let re = store.get_genesis("acme", "mesh-1").await.unwrap().unwrap();
    assert_eq!(re, updated);

    // Delete
    assert!(store.delete_genesis("acme", "mesh-1").await.unwrap());
    assert!(store.get_genesis("acme", "mesh-1").await.unwrap().is_none());

    drop_test_db(&db).await;
}

// ── CDC cursors ───────────────────────────────────────────────

#[tokio::test]
async fn pg_cursor_set_and_get() {
    let Some((url, db)) = create_test_db("cursors").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("acme")).await.unwrap();

    // Initially none
    assert!(store
        .get_cursor("acme", "mesh-1", "doc-1")
        .await
        .unwrap()
        .is_none());

    // Set
    store
        .set_cursor("acme", "mesh-1", "doc-1", "hash-abc")
        .await
        .unwrap();
    let cursor = store
        .get_cursor("acme", "mesh-1", "doc-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cursor, "hash-abc");

    // Update (upsert)
    store
        .set_cursor("acme", "mesh-1", "doc-1", "hash-def")
        .await
        .unwrap();
    let updated = store
        .get_cursor("acme", "mesh-1", "doc-1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(updated, "hash-def");

    drop_test_db(&db).await;
}

// ── Org isolation ─────────────────────────────────────────────

#[tokio::test]
async fn pg_org_isolation() {
    let Some((url, db)) = create_test_db("org_isolation").await else {
        return;
    };
    let store = open_store(&url).await;

    store.create_org(&sample_org("alpha")).await.unwrap();
    store.create_org(&sample_org("bravo")).await.unwrap();

    store
        .create_formation(
            "alpha",
            &FormationConfig {
                app_id: "mesh-1".into(),
                mesh_id: "alpha-mesh".into(),
                enrollment_policy: EnrollmentPolicy::Open,
            },
        )
        .await
        .unwrap();
    store
        .store_genesis("alpha", "mesh-1", b"alpha-genesis")
        .await
        .unwrap();

    // Bravo should not see alpha's data
    assert!(store.list_formations("bravo").await.unwrap().is_empty());
    assert!(store
        .get_formation("bravo", "mesh-1")
        .await
        .unwrap()
        .is_none());
    assert!(store
        .get_genesis("bravo", "mesh-1")
        .await
        .unwrap()
        .is_none());

    // Alpha's data is intact
    assert_eq!(store.list_formations("alpha").await.unwrap().len(), 1);

    drop_test_db(&db).await;
}

// ── Envelope encryption with Postgres ─────────────────────────

#[tokio::test]
async fn pg_envelope_encryption_roundtrip() {
    let Some((url, db)) = create_test_db("encryption").await else {
        return;
    };

    let kek_hex = "aa".repeat(32);
    let config = make_config(&url, Some(&kek_hex));

    // Create org + formation with encryption via TenantManager
    let mgr = TenantManager::new(&config).await.unwrap();
    mgr.create_org("enc-org".into(), "Encrypted Org".into())
        .await
        .unwrap();
    let formation = mgr
        .create_formation("enc-org", "enc-mesh".into(), EnrollmentPolicy::Open)
        .await
        .unwrap();

    // Raw bytes in Postgres should be PENV envelope
    let store = open_store(&url).await;
    let raw = store
        .get_genesis("enc-org", "enc-mesh")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &raw[..4],
        b"PENV",
        "Genesis should be encrypted in Postgres"
    );

    // Loading through TenantManager decrypts transparently
    let genesis = mgr.load_genesis("enc-org", "enc-mesh").await.unwrap();
    assert_eq!(genesis.mesh_id(), formation.mesh_id);

    drop_test_db(&db).await;
}

// ── migrate-keys with Postgres ────────────────────────────────

#[tokio::test]
async fn pg_migrate_keys() {
    let Some((url, db)) = create_test_db("migrate_keys").await else {
        return;
    };

    // Create plaintext genesis
    let config_plain = make_config(&url, None);
    {
        let mgr = TenantManager::new(&config_plain).await.unwrap();
        mgr.create_org("mig-org".into(), "Migration Org".into())
            .await
            .unwrap();
        mgr.create_formation("mig-org", "mig-mesh".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
    }

    // Verify plaintext
    {
        let store = open_store(&url).await;
        let raw = store
            .get_genesis("mig-org", "mig-mesh")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(&raw[..4], b"PENV", "Should be plaintext before migration");
    }

    // Run migration
    let kek_hex = "bb".repeat(32);
    let config_enc = make_config(&url, Some(&kek_hex));
    peat_gateway::cli::migrate_keys(&config_enc, false)
        .await
        .unwrap();

    // Verify encrypted
    {
        let store = open_store(&url).await;
        let raw = store
            .get_genesis("mig-org", "mig-mesh")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&raw[..4], b"PENV", "Should be encrypted after migration");
    }

    // Verify loadable
    let mgr = TenantManager::new(&config_enc).await.unwrap();
    let genesis = mgr.load_genesis("mig-org", "mig-mesh").await.unwrap();
    assert!(!genesis.mesh_id().is_empty());

    drop_test_db(&db).await;
}
