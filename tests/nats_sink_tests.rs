//! Integration tests for NATS CDC sink delivery.
//!
//! Requires a running NATS server. Set `NATS_URL` env var or defaults to
//! `nats://localhost:4222`. Skipped automatically if NATS is unreachable.

#![cfg(feature = "nats")]

use std::time::Duration;

use futures::StreamExt;
use peat_gateway::cdc::CdcEngine;
use peat_gateway::config::{CdcConfig, GatewayConfig, StorageConfig};
use peat_gateway::tenant::models::CdcEvent;
use peat_gateway::tenant::TenantManager;
use serde_json::json;

fn nats_url() -> String {
    std::env::var("NATS_URL").unwrap_or_else(|_| "nats://localhost:4222".into())
}

/// Try to connect to NATS. Returns None if unreachable (so tests can skip gracefully).
async fn try_nats_client() -> Option<async_nats::Client> {
    let url = nats_url();
    match tokio::time::timeout(Duration::from_secs(3), async_nats::connect(&url)).await {
        Ok(Ok(client)) => Some(client),
        _ => {
            eprintln!("NATS not available at {url}, skipping NATS sink tests");
            None
        }
    }
}

/// Spin up a TenantManager + CdcEngine backed by temp redb, connected to NATS.
async fn setup() -> Option<(TenantManager, CdcEngine, tempfile::TempDir)> {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.redb");

    let config = GatewayConfig {
        bind_addr: "127.0.0.1:0".into(),
        storage: StorageConfig::Redb {
            path: db_path.to_str().unwrap().into(),
        },
        cdc: CdcConfig {
            nats_url: Some(nats_url()),
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
    match CdcEngine::new(&config, tenant_mgr.clone()).await {
        Ok(engine) => Some((tenant_mgr, engine, dir)),
        Err(e) => {
            eprintln!("Failed to init CDC engine with NATS: {e}, skipping");
            None
        }
    }
}

fn sample_event(org_id: &str, app_id: &str) -> CdcEvent {
    CdcEvent {
        org_id: org_id.into(),
        app_id: app_id.into(),
        document_id: "doc-001".into(),
        change_hash: "abc123deadbeef".into(),
        actor_id: "peer-42".into(),
        timestamp_ms: 1700000000000,
        patches: json!([{"op": "add", "path": "/key", "value": "hello"}]),
    }
}

// ── Tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn publish_event_arrives_on_nats_subject() {
    let Some(nats_client) = try_nats_client().await else {
        return;
    };
    let Some((tenant_mgr, engine, _dir)) = setup().await else {
        return;
    };

    // Create org + formation + NATS sink
    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation(
            "acme",
            "logistics".into(),
            peat_gateway::tenant::models::EnrollmentPolicy::Open,
        )
        .await
        .unwrap();
    tenant_mgr
        .create_sink(
            "acme",
            peat_gateway::tenant::models::CdcSinkType::Nats {
                subject_prefix: "peat.acme".into(),
            },
        )
        .await
        .unwrap();

    // Subscribe BEFORE publishing
    let mut sub = nats_client
        .subscribe("peat.acme.logistics.doc-001")
        .await
        .unwrap();

    // Publish via CDC engine
    let event = sample_event("acme", "logistics");
    engine.publish(&event).await.unwrap();

    // Receive with timeout
    let msg = tokio::time::timeout(Duration::from_secs(5), sub.next())
        .await
        .expect("Timed out waiting for NATS message")
        .expect("Subscription closed unexpectedly");

    // Verify payload
    let received: CdcEvent = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(received.org_id, "acme");
    assert_eq!(received.app_id, "logistics");
    assert_eq!(received.document_id, "doc-001");
    assert_eq!(received.change_hash, "abc123deadbeef");
    assert_eq!(received.actor_id, "peer-42");

    // Verify dedup header
    let headers = msg.headers.expect("Expected headers on NATS message");
    assert_eq!(
        headers
            .get(async_nats::header::NATS_MESSAGE_ID)
            .map(|v| v.as_str()),
        Some("abc123deadbeef")
    );
}

#[tokio::test]
async fn disabled_sink_does_not_publish() {
    let Some(nats_client) = try_nats_client().await else {
        return;
    };
    let Some((tenant_mgr, engine, _dir)) = setup().await else {
        return;
    };

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation(
            "acme",
            "logistics".into(),
            peat_gateway::tenant::models::EnrollmentPolicy::Open,
        )
        .await
        .unwrap();

    // Create sink, then disable it
    let sink = tenant_mgr
        .create_sink(
            "acme",
            peat_gateway::tenant::models::CdcSinkType::Nats {
                subject_prefix: "peat.disabled".into(),
            },
        )
        .await
        .unwrap();
    tenant_mgr
        .toggle_sink("acme", &sink.sink_id, false)
        .await
        .unwrap();

    let mut sub = nats_client
        .subscribe("peat.disabled.logistics.>")
        .await
        .unwrap();

    engine
        .publish(&sample_event("acme", "logistics"))
        .await
        .unwrap();

    // Should NOT receive anything
    let result = tokio::time::timeout(Duration::from_millis(500), sub.next()).await;
    assert!(
        result.is_err(),
        "Expected timeout (no message), but got a message"
    );
}

#[tokio::test]
async fn multiple_sinks_fan_out() {
    let Some(nats_client) = try_nats_client().await else {
        return;
    };
    let Some((tenant_mgr, engine, _dir)) = setup().await else {
        return;
    };

    tenant_mgr
        .create_org("acme".into(), "Acme Corp".into())
        .await
        .unwrap();
    tenant_mgr
        .create_formation(
            "acme",
            "comms".into(),
            peat_gateway::tenant::models::EnrollmentPolicy::Open,
        )
        .await
        .unwrap();

    // Two NATS sinks with different subject prefixes
    tenant_mgr
        .create_sink(
            "acme",
            peat_gateway::tenant::models::CdcSinkType::Nats {
                subject_prefix: "sink-a".into(),
            },
        )
        .await
        .unwrap();
    tenant_mgr
        .create_sink(
            "acme",
            peat_gateway::tenant::models::CdcSinkType::Nats {
                subject_prefix: "sink-b".into(),
            },
        )
        .await
        .unwrap();

    let mut sub_a = nats_client.subscribe("sink-a.comms.>").await.unwrap();
    let mut sub_b = nats_client.subscribe("sink-b.comms.>").await.unwrap();

    let event = CdcEvent {
        org_id: "acme".into(),
        app_id: "comms".into(),
        document_id: "doc-fanout".into(),
        change_hash: "hash-fanout-001".into(),
        actor_id: "peer-1".into(),
        timestamp_ms: 1700000000000,
        patches: json!({"changed": true}),
    };
    engine.publish(&event).await.unwrap();

    let msg_a = tokio::time::timeout(Duration::from_secs(5), sub_a.next())
        .await
        .expect("Timed out on sink-a")
        .unwrap();
    let msg_b = tokio::time::timeout(Duration::from_secs(5), sub_b.next())
        .await
        .expect("Timed out on sink-b")
        .unwrap();

    let ev_a: CdcEvent = serde_json::from_slice(&msg_a.payload).unwrap();
    let ev_b: CdcEvent = serde_json::from_slice(&msg_b.payload).unwrap();
    assert_eq!(ev_a.document_id, "doc-fanout");
    assert_eq!(ev_b.document_id, "doc-fanout");
}

#[tokio::test]
async fn org_isolation_no_cross_delivery() {
    let Some(nats_client) = try_nats_client().await else {
        return;
    };
    let Some((tenant_mgr, engine, _dir)) = setup().await else {
        return;
    };

    // Two orgs, each with a formation and NATS sink
    for (org, prefix) in [("alpha", "ns.alpha"), ("bravo", "ns.bravo")] {
        tenant_mgr.create_org(org.into(), org.into()).await.unwrap();
        tenant_mgr
            .create_formation(
                org,
                "mesh".into(),
                peat_gateway::tenant::models::EnrollmentPolicy::Open,
            )
            .await
            .unwrap();
        tenant_mgr
            .create_sink(
                org,
                peat_gateway::tenant::models::CdcSinkType::Nats {
                    subject_prefix: prefix.into(),
                },
            )
            .await
            .unwrap();
    }

    let mut sub_alpha = nats_client.subscribe("ns.alpha.>").await.unwrap();
    let mut sub_bravo = nats_client.subscribe("ns.bravo.>").await.unwrap();

    // Publish event for alpha only
    let event = CdcEvent {
        org_id: "alpha".into(),
        app_id: "mesh".into(),
        document_id: "doc-isolated".into(),
        change_hash: "hash-isolated".into(),
        actor_id: "peer-a".into(),
        timestamp_ms: 1700000000000,
        patches: json!(null),
    };
    engine.publish(&event).await.unwrap();

    // Alpha should get it
    let msg = tokio::time::timeout(Duration::from_secs(5), sub_alpha.next())
        .await
        .expect("Alpha should receive the event")
        .unwrap();
    let received: CdcEvent = serde_json::from_slice(&msg.payload).unwrap();
    assert_eq!(received.org_id, "alpha");

    // Bravo should NOT
    let result = tokio::time::timeout(Duration::from_millis(500), sub_bravo.next()).await;
    assert!(result.is_err(), "Bravo should not receive alpha's event");
}
