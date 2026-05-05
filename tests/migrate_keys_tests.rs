//! Integration tests for the `migrate-keys` subcommand.
//!
//! Verifies that plaintext genesis records are encrypted in-place and that
//! already-encrypted records are left untouched.

use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::models::EnrollmentPolicy;
use peat_gateway::tenant::TenantManager;

fn base_config(db_path: &std::path::Path) -> GatewayConfig {
    GatewayConfig {
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
    }
}

#[tokio::test]
async fn migrate_encrypts_plaintext_genesis_records() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let config = base_config(&db_path);

    // Create orgs + formations WITHOUT encryption (no KEK)
    {
        let mgr = TenantManager::new(&config).await.unwrap();
        mgr.create_org("alpha".into(), "Alpha Corp".into())
            .await
            .unwrap();
        mgr.create_formation("alpha", "mesh-a".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
        mgr.create_formation("alpha", "mesh-b".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();

        mgr.create_org("bravo".into(), "Bravo Corp".into())
            .await
            .unwrap();
        mgr.create_formation("bravo", "mesh-c".into(), EnrollmentPolicy::Controlled)
            .await
            .unwrap();
    }

    // Verify records are plaintext (no PENV header)
    {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        for (org, app) in [
            ("alpha", "mesh-a"),
            ("alpha", "mesh-b"),
            ("bravo", "mesh-c"),
        ] {
            let raw = store.get_genesis(org, app).await.unwrap().unwrap();
            assert_ne!(
                &raw[..4],
                b"PENV",
                "{org}/{app} should be plaintext before migration"
            );
        }
    }

    // Run migration with KEK
    let mut config_with_kek = base_config(&db_path);
    config_with_kek.kek = Some("cc".repeat(32));
    peat_gateway::cli::migrate_keys(&config_with_kek, false)
        .await
        .unwrap();

    // Verify all records are now encrypted
    {
        let store = peat_gateway::storage::open(&config_with_kek.storage)
            .await
            .unwrap();
        for (org, app) in [
            ("alpha", "mesh-a"),
            ("alpha", "mesh-b"),
            ("bravo", "mesh-c"),
        ] {
            let raw = store.get_genesis(org, app).await.unwrap().unwrap();
            assert_eq!(
                &raw[..4],
                b"PENV",
                "{org}/{app} should be encrypted after migration"
            );
        }
    }

    // Verify genesis is still loadable through TenantManager with KEK
    {
        let mgr = TenantManager::new(&config_with_kek).await.unwrap();
        for (org, app) in [
            ("alpha", "mesh-a"),
            ("alpha", "mesh-b"),
            ("bravo", "mesh-c"),
        ] {
            let genesis = mgr.load_genesis(org, app).await.unwrap();
            assert!(
                !genesis.mesh_id().is_empty(),
                "{org}/{app} genesis should decode"
            );
        }
    }
}

#[tokio::test]
async fn migrate_skips_already_encrypted_records() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let kek_hex = "dd".repeat(32);

    // Create with encryption enabled
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
        kek: Some(kek_hex.clone()),
        kms_key_arn: None,
        vault_addr: None,
        vault_token: None,
        vault_transit_key: None,
        mesh_brokers: vec![],
        mesh_poll_interval_ms: 5_000,
    };

    {
        let mgr = TenantManager::new(&config).await.unwrap();
        mgr.create_org("acme".into(), "Acme Corp".into())
            .await
            .unwrap();
        mgr.create_formation("acme", "mesh-x".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
    }

    // Capture the encrypted bytes before migration
    let before = {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        store.get_genesis("acme", "mesh-x").await.unwrap().unwrap()
    };
    assert_eq!(&before[..4], b"PENV");

    // Run migration — should skip this record
    peat_gateway::cli::migrate_keys(&config, false)
        .await
        .unwrap();

    // Bytes should be identical (not re-encrypted)
    let after = {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        store.get_genesis("acme", "mesh-x").await.unwrap().unwrap()
    };
    assert_eq!(
        before, after,
        "Already-encrypted record should not be re-encrypted"
    );
}

#[tokio::test]
async fn migrate_mixed_plaintext_and_encrypted() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let kek_hex = "ee".repeat(32);

    // Create one formation without encryption
    {
        let config = base_config(&db_path);
        let mgr = TenantManager::new(&config).await.unwrap();
        mgr.create_org("mixed".into(), "Mixed Corp".into())
            .await
            .unwrap();
        mgr.create_formation("mixed", "plain-app".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
    }

    // Create another formation with encryption
    {
        let config = GatewayConfig {
            admin_token: None,
            kek: Some(kek_hex.clone()),
            ..base_config(&db_path)
        };
        let mgr = TenantManager::new(&config).await.unwrap();
        mgr.create_formation("mixed", "enc-app".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
    }

    // Verify mixed state
    {
        let store = peat_gateway::storage::open(&base_config(&db_path).storage)
            .await
            .unwrap();
        let plain = store
            .get_genesis("mixed", "plain-app")
            .await
            .unwrap()
            .unwrap();
        let enc = store
            .get_genesis("mixed", "enc-app")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(&plain[..4], b"PENV", "plain-app should be plaintext");
        assert_eq!(&enc[..4], b"PENV", "enc-app should be encrypted");
    }

    // Run migration
    let config_with_kek = GatewayConfig {
        admin_token: None,
        kek: Some(kek_hex.clone()),
        ..base_config(&db_path)
    };
    peat_gateway::cli::migrate_keys(&config_with_kek, false)
        .await
        .unwrap();

    // Both should now be encrypted
    {
        let store = peat_gateway::storage::open(&config_with_kek.storage)
            .await
            .unwrap();
        let plain = store
            .get_genesis("mixed", "plain-app")
            .await
            .unwrap()
            .unwrap();
        let enc = store
            .get_genesis("mixed", "enc-app")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            &plain[..4],
            b"PENV",
            "plain-app should be encrypted after migration"
        );
        assert_eq!(&enc[..4], b"PENV", "enc-app should still be encrypted");
    }

    // Both should load through TenantManager
    {
        let mgr = TenantManager::new(&config_with_kek).await.unwrap();
        let g1 = mgr.load_genesis("mixed", "plain-app").await.unwrap();
        let g2 = mgr.load_genesis("mixed", "enc-app").await.unwrap();
        assert!(!g1.mesh_id().is_empty());
        assert!(!g2.mesh_id().is_empty());
    }
}

#[tokio::test]
async fn migrate_dry_run_does_not_modify_records() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let config = base_config(&db_path);

    // Create a plaintext formation
    {
        let mgr = TenantManager::new(&config).await.unwrap();
        mgr.create_org("dry".into(), "Dry Corp".into())
            .await
            .unwrap();
        mgr.create_formation("dry", "app-1".into(), EnrollmentPolicy::Open)
            .await
            .unwrap();
    }

    // Capture plaintext bytes
    let before = {
        let store = peat_gateway::storage::open(&config.storage).await.unwrap();
        store.get_genesis("dry", "app-1").await.unwrap().unwrap()
    };
    assert_ne!(&before[..4], b"PENV");

    // Run dry-run migration
    let config_with_kek = GatewayConfig {
        admin_token: None,
        kek: Some("aa".repeat(32)),
        ..base_config(&db_path)
    };
    peat_gateway::cli::migrate_keys(&config_with_kek, true)
        .await
        .unwrap();

    // Bytes should be unchanged — still plaintext
    let after = {
        let store = peat_gateway::storage::open(&config_with_kek.storage)
            .await
            .unwrap();
        store.get_genesis("dry", "app-1").await.unwrap().unwrap()
    };
    assert_eq!(before, after, "Dry run should not modify any records");
    assert_ne!(&after[..4], b"PENV", "Record should still be plaintext");
}

#[tokio::test]
async fn migrate_fails_without_kek() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");
    let config = base_config(&db_path);

    let result = peat_gateway::cli::migrate_keys(&config, false).await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("PEAT_KEK") || err_msg.contains("No key provider configured"),
        "Error should mention key provider configuration"
    );
}

#[tokio::test]
async fn migrate_no_formations_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

    // Create org with no formations
    {
        let config = base_config(&db_path);
        let mgr = TenantManager::new(&config).await.unwrap();
        mgr.create_org("empty".into(), "Empty Corp".into())
            .await
            .unwrap();
    }

    let config = GatewayConfig {
        admin_token: None,
        kek: Some("ff".repeat(32)),
        ..base_config(&db_path)
    };
    // Should succeed with nothing to migrate
    peat_gateway::cli::migrate_keys(&config, false)
        .await
        .unwrap();
}
