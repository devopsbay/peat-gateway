//! Load testing harness for peat-gateway.
//!
//! Feature-gated behind `--features loadtest`. Spawns a local gateway backed by
//! a temp redb, runs concurrent workers against it, and reports latency /
//! throughput / error stats.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::Result;
use reqwest::Client;
use serde::Serialize;
use serde_json::json;
use tokio::sync::{mpsc, watch};

use crate::api;
use crate::config::{CdcConfig, GatewayConfig, StorageConfig};
use crate::tenant::TenantManager;

// ── Data types ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct RequestSample {
    pub endpoint: String,
    pub status: u16,
    pub latency_us: u64,
    pub timestamp_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct EndpointStats {
    pub endpoint: String,
    pub count: usize,
    pub errors: usize,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct LoadTestReport {
    pub scenario: String,
    pub concurrency: usize,
    pub duration_secs: u64,
    pub total_requests: usize,
    pub successful: usize,
    pub failed: usize,
    pub throughput_rps: f64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
    pub error_breakdown: HashMap<u16, usize>,
    pub endpoints: Vec<EndpointStats>,
    pub samples: Vec<RequestSample>,
}

// ── Percentile ──────────────────────────────────────────────────

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((p / 100.0) * (sorted.len() as f64 - 1.0)).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

// ── Aggregation ─────────────────────────────────────────────────

fn aggregate(
    samples: Vec<RequestSample>,
    scenario: &str,
    concurrency: usize,
    duration_secs: u64,
) -> LoadTestReport {
    let total_requests = samples.len();
    let successful = samples.iter().filter(|s| s.status < 400).count();
    let failed = total_requests - successful;

    let mut all_latencies: Vec<u64> = samples.iter().map(|s| s.latency_us).collect();
    all_latencies.sort_unstable();

    let mean_us = if all_latencies.is_empty() {
        0
    } else {
        all_latencies.iter().sum::<u64>() / all_latencies.len() as u64
    };

    // Compute actual duration from sample timestamps
    let actual_duration = if samples.len() >= 2 {
        let min_ts = samples.iter().map(|s| s.timestamp_ms).min().unwrap_or(0);
        let max_ts = samples.iter().map(|s| s.timestamp_ms).max().unwrap_or(0);
        let dur = (max_ts - min_ts) as f64 / 1000.0;
        if dur > 0.0 {
            dur
        } else {
            duration_secs as f64
        }
    } else {
        duration_secs as f64
    };

    let throughput_rps = total_requests as f64 / actual_duration;

    // Error breakdown
    let mut error_breakdown: HashMap<u16, usize> = HashMap::new();
    for s in &samples {
        if s.status >= 400 {
            *error_breakdown.entry(s.status).or_default() += 1;
        }
    }

    // Per-endpoint stats
    let mut by_endpoint: HashMap<String, Vec<&RequestSample>> = HashMap::new();
    for s in &samples {
        by_endpoint.entry(s.endpoint.clone()).or_default().push(s);
    }

    let mut endpoints: Vec<EndpointStats> = by_endpoint
        .into_iter()
        .map(|(ep, ep_samples)| {
            let mut lats: Vec<u64> = ep_samples.iter().map(|s| s.latency_us).collect();
            lats.sort_unstable();
            let ep_errors = ep_samples
                .iter()
                .filter(|s| s.status >= 400 || s.status == 0)
                .count();
            let ep_mean = if lats.is_empty() {
                0
            } else {
                lats.iter().sum::<u64>() / lats.len() as u64
            };
            EndpointStats {
                endpoint: ep,
                count: ep_samples.len(),
                errors: ep_errors,
                p50_us: percentile(&lats, 50.0),
                p95_us: percentile(&lats, 95.0),
                p99_us: percentile(&lats, 99.0),
                max_us: *lats.last().unwrap_or(&0),
                mean_us: ep_mean,
            }
        })
        .collect();
    endpoints.sort_by(|a, b| b.count.cmp(&a.count));

    LoadTestReport {
        scenario: scenario.to_string(),
        concurrency,
        duration_secs,
        total_requests,
        successful,
        failed,
        throughput_rps,
        p50_us: percentile(&all_latencies, 50.0),
        p95_us: percentile(&all_latencies, 95.0),
        p99_us: percentile(&all_latencies, 99.0),
        max_us: *all_latencies.last().unwrap_or(&0),
        mean_us,
        error_breakdown,
        endpoints,
        samples,
    }
}

// ── Report output ───────────────────────────────────────────────

fn print_report(report: &LoadTestReport) {
    let ok_pct = if report.total_requests > 0 {
        (report.successful as f64 / report.total_requests as f64) * 100.0
    } else {
        0.0
    };

    eprintln!();
    eprintln!(
        "peat-gateway load test — {}, {} workers, {}s",
        report.scenario, report.concurrency, report.duration_secs
    );
    eprintln!();
    eprintln!(
        "  requests:  {} total, {} ok ({:.1}%), {} err",
        report.total_requests, report.successful, ok_pct, report.failed
    );
    eprintln!("  throughput: {:.1} req/s", report.throughput_rps);
    eprintln!();
    eprintln!(
        "  {:20} {:>8} {:>8} {:>8} {:>8}",
        "latency (μs)", "p50", "p95", "p99", "max"
    );
    eprintln!(
        "  {:20} {:>8} {:>8} {:>8} {:>8}",
        "all", report.p50_us, report.p95_us, report.p99_us, report.max_us
    );
    eprintln!();
    eprintln!(
        "  {:30} {:>8} {:>8} {:>8} {:>8}",
        "endpoint", "count", "p50", "p95", "errors"
    );
    for ep in &report.endpoints {
        eprintln!(
            "  {:30} {:>8} {:>8} {:>8} {:>8}",
            ep.endpoint, ep.count, ep.p50_us, ep.p95_us, ep.errors
        );
    }
    eprintln!();
}

fn write_json(report: &LoadTestReport, path: &str) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    std::fs::write(path, json)?;
    eprintln!("JSON report written to {path}");
    Ok(())
}

// ── Server spawn ────────────────────────────────────────────────

pub async fn spawn_test_server() -> Result<(String, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let db_path = dir.path().join("loadtest.redb");

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

    let tenant_mgr = TenantManager::new(&config).await?;
    let app = api::app(tenant_mgr);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let base = format!("http://{addr}");
    Ok((base, dir))
}

// ── Operations ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Operation {
    CreateOrg,
    GetOrg,
    ListOrgs,
    CreateFormation,
    GetFormation,
    ListFormations,
    DeleteFormation,
    CreateToken,
    ListTokens,
    CreateSink,
    ListSinks,
    ToggleSink,
    HealthCheck,
}

struct WorkerState {
    worker_id: usize,
    org_id: String,
    app_ids: Vec<String>,
    token_ids: Vec<String>,
    sink_ids: Vec<String>,
    formation_counter: usize,
}

impl WorkerState {
    fn new(worker_id: usize, org_id: String) -> Self {
        Self {
            worker_id,
            org_id,
            app_ids: Vec::new(),
            token_ids: Vec::new(),
            sink_ids: Vec::new(),
            formation_counter: 0,
        }
    }

    fn next_app_id(&mut self) -> String {
        self.formation_counter += 1;
        format!("w{}-app-{}", self.worker_id, self.formation_counter)
    }
}

/// Execute a single operation. Returns `None` when the worker has no state to
/// operate on (e.g. GetFormation with an empty app_ids list) — callers should
/// skip recording a sample rather than logging a fake failure.
async fn execute_op(
    client: &Client,
    base: &str,
    state: &mut WorkerState,
    op: Operation,
) -> Option<(String, u16)> {
    match op {
        Operation::CreateOrg => {
            let resp = client
                .post(format!("{base}/orgs"))
                .json(&json!({"org_id": &state.org_id, "display_name": &state.org_id}))
                .send()
                .await
                .ok()?;
            Some(("POST /orgs".into(), resp.status().as_u16()))
        }
        Operation::GetOrg => {
            let resp = client
                .get(format!("{base}/orgs/{}", state.org_id))
                .send()
                .await
                .ok()?;
            Some(("GET /orgs/:id".into(), resp.status().as_u16()))
        }
        Operation::ListOrgs => {
            let resp = client.get(format!("{base}/orgs")).send().await.ok()?;
            Some(("GET /orgs".into(), resp.status().as_u16()))
        }
        Operation::CreateFormation => {
            let app_id = state.next_app_id();
            let resp = client
                .post(format!("{base}/orgs/{}/formations", state.org_id))
                .json(&json!({"app_id": &app_id}))
                .send()
                .await
                .ok()?;
            let status = resp.status().as_u16();
            if status < 400 {
                state.app_ids.push(app_id);
            }
            Some(("POST /orgs/:id/formations".into(), status))
        }
        Operation::GetFormation => {
            if state.app_ids.is_empty() {
                return None;
            }
            let idx = state.formation_counter % state.app_ids.len();
            let app_id = state.app_ids[idx].clone();
            let resp = client
                .get(format!("{base}/orgs/{}/formations/{app_id}", state.org_id))
                .send()
                .await
                .ok()?;
            Some((
                "GET /orgs/:id/formations/:id".into(),
                resp.status().as_u16(),
            ))
        }
        Operation::ListFormations => {
            let resp = client
                .get(format!("{base}/orgs/{}/formations", state.org_id))
                .send()
                .await
                .ok()?;
            Some(("GET /orgs/:id/formations".into(), resp.status().as_u16()))
        }
        Operation::DeleteFormation => {
            let app_id = state.app_ids.pop()?;
            let resp = client
                .delete(format!("{base}/orgs/{}/formations/{app_id}", state.org_id))
                .send()
                .await
                .ok()?;
            Some((
                "DELETE /orgs/:id/formations/:id".into(),
                resp.status().as_u16(),
            ))
        }
        Operation::CreateToken => {
            if state.app_ids.is_empty() {
                return None;
            }
            let app_id = state.app_ids[0].clone();
            let label = format!("w{}-tok-{}", state.worker_id, state.token_ids.len());
            let resp = client
                .post(format!("{base}/orgs/{}/tokens", state.org_id))
                .json(&json!({"app_id": &app_id, "label": &label}))
                .send()
                .await
                .ok()?;
            let status = resp.status().as_u16();
            if status < 400 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(tid) = body["token_id"].as_str() {
                        state.token_ids.push(tid.to_string());
                    }
                }
            }
            Some(("POST /orgs/:id/tokens".into(), status))
        }
        Operation::ListTokens => {
            if state.app_ids.is_empty() {
                return None;
            }
            let app_id = &state.app_ids[0];
            let resp = client
                .get(format!(
                    "{base}/orgs/{}/formations/{app_id}/tokens",
                    state.org_id
                ))
                .send()
                .await
                .ok()?;
            Some((
                "GET /orgs/:id/formations/:id/tokens".into(),
                resp.status().as_u16(),
            ))
        }
        Operation::CreateSink => {
            let prefix = format!(
                "peat.{}.w{}.{}",
                state.org_id,
                state.worker_id,
                state.sink_ids.len()
            );
            let resp = client
                .post(format!("{base}/orgs/{}/sinks", state.org_id))
                .json(&json!({"sink_type": {"Nats": {"subject_prefix": prefix}}}))
                .send()
                .await
                .ok()?;
            let status = resp.status().as_u16();
            if status < 400 {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    if let Some(sid) = body["sink_id"].as_str() {
                        state.sink_ids.push(sid.to_string());
                    }
                }
            }
            Some(("POST /orgs/:id/sinks".into(), status))
        }
        Operation::ListSinks => {
            let resp = client
                .get(format!("{base}/orgs/{}/sinks", state.org_id))
                .send()
                .await
                .ok()?;
            Some(("GET /orgs/:id/sinks".into(), resp.status().as_u16()))
        }
        Operation::ToggleSink => {
            let sink_id = state.sink_ids.first()?.clone();
            let resp = client
                .patch(format!("{base}/orgs/{}/sinks/{sink_id}", state.org_id))
                .json(&json!({"enabled": false}))
                .send()
                .await
                .ok()?;
            Some(("PATCH /orgs/:id/sinks/:id".into(), resp.status().as_u16()))
        }
        Operation::HealthCheck => {
            let resp = client.get(format!("{base}/health")).send().await.ok()?;
            Some(("GET /health".into(), resp.status().as_u16()))
        }
    }
}

// ── Scenario selection ──────────────────────────────────────────

fn pick_mixed_op(roll: u8, state: &WorkerState) -> Operation {
    match roll % 100 {
        0..=14 => Operation::ListOrgs,
        15..=29 => {
            if state.app_ids.is_empty() {
                Operation::CreateFormation
            } else {
                Operation::GetFormation
            }
        }
        30..=44 => Operation::CreateFormation,
        45..=54 => {
            if state.app_ids.is_empty() {
                Operation::CreateFormation
            } else {
                Operation::ListFormations
            }
        }
        55..=64 => {
            if state.app_ids.is_empty() {
                Operation::CreateFormation
            } else {
                Operation::CreateToken
            }
        }
        65..=74 => Operation::CreateSink,
        75..=84 => {
            if state.app_ids.is_empty() {
                Operation::CreateFormation
            } else {
                Operation::DeleteFormation
            }
        }
        85..=94 => Operation::ListSinks,
        _ => Operation::HealthCheck,
    }
}

fn pick_read_heavy_op(roll: u8, state: &WorkerState) -> Operation {
    match roll % 100 {
        0..=19 => Operation::ListOrgs,
        20..=39 => {
            if state.app_ids.is_empty() {
                Operation::CreateFormation
            } else {
                Operation::GetFormation
            }
        }
        40..=59 => {
            if state.app_ids.is_empty() {
                Operation::CreateFormation
            } else {
                Operation::ListFormations
            }
        }
        60..=69 => Operation::GetOrg,
        70..=79 => Operation::ListSinks,
        80..=89 => Operation::CreateFormation,
        90..=94 => {
            if state.app_ids.is_empty() {
                Operation::CreateFormation
            } else {
                Operation::CreateToken
            }
        }
        _ => Operation::HealthCheck,
    }
}

// ── Worker ──────────────────────────────────────────────────────

async fn run_worker(
    worker_id: usize,
    client: Client,
    base: String,
    org_id: String,
    scenario: String,
    tx: mpsc::UnboundedSender<RequestSample>,
    mut stop: watch::Receiver<bool>,
) {
    let mut state = WorkerState::new(worker_id, org_id);
    let epoch = Instant::now();

    // Setup: create org, raise quotas so the test isn't bottlenecked by defaults,
    // then seed a couple of formations + a sink for read operations to target.
    let _ = execute_op(&client, &base, &mut state, Operation::CreateOrg).await;

    // Raise quotas — default max_formations=10 / max_cdc_sinks=5 are hit almost
    // instantly under load, turning the test into a quota-error benchmark.
    let _ = client
        .patch(format!("{base}/orgs/{}", state.org_id))
        .json(&json!({
            "quotas": {
                "max_formations": 100_000,
                "max_peers_per_formation": 100,
                "max_documents_per_formation": 10_000,
                "max_cdc_sinks": 100_000
            }
        }))
        .send()
        .await;

    let _ = execute_op(&client, &base, &mut state, Operation::CreateFormation).await;
    let _ = execute_op(&client, &base, &mut state, Operation::CreateFormation).await;
    let _ = execute_op(&client, &base, &mut state, Operation::CreateSink).await;

    let mut counter: u8 = (worker_id as u8).wrapping_mul(37); // different starting point per worker

    loop {
        if *stop.borrow_and_update() {
            break;
        }

        let op = match scenario.as_str() {
            "burst" => Operation::CreateFormation,
            "read-heavy" => pick_read_heavy_op(counter, &state),
            _ => pick_mixed_op(counter, &state),
        };
        counter = counter.wrapping_add(7);

        let req_start = Instant::now();
        if let Some((endpoint, status)) = execute_op(&client, &base, &mut state, op).await {
            let latency_us = req_start.elapsed().as_micros() as u64;
            let timestamp_ms = epoch.elapsed().as_millis() as u64;

            let _ = tx.send(RequestSample {
                endpoint,
                status,
                latency_us,
                timestamp_ms,
            });
        }
    }
}

// ── Orchestrator ────────────────────────────────────────────────

pub async fn run(
    concurrency: usize,
    duration_secs: u64,
    scenario: String,
    orgs: usize,
    output: Option<String>,
) -> Result<LoadTestReport> {
    let (base, _dir) = spawn_test_server().await?;
    let client = Client::new();

    let (tx, mut rx) = mpsc::unbounded_channel::<RequestSample>();
    let (stop_tx, stop_rx) = watch::channel(false);

    // Assign org IDs: multi-org round-robins across N orgs, others get one per worker
    let org_ids: Vec<String> = if scenario == "multi-org" {
        (0..orgs).map(|i| format!("org-{i}")).collect()
    } else {
        (0..concurrency)
            .map(|i| format!("worker-org-{i}"))
            .collect()
    };

    // Spawn workers
    let mut handles = Vec::new();
    for i in 0..concurrency {
        let org_id = if scenario == "multi-org" {
            org_ids[i % org_ids.len()].clone()
        } else {
            org_ids[i].clone()
        };
        let worker_scenario = if scenario == "multi-org" {
            "mixed".to_string()
        } else {
            scenario.clone()
        };

        handles.push(tokio::spawn(run_worker(
            i,
            client.clone(),
            base.clone(),
            org_id,
            worker_scenario,
            tx.clone(),
            stop_rx.clone(),
        )));
    }

    // Drop our sender so the channel closes when all workers finish
    drop(tx);

    // Run for the requested duration, then signal stop
    tokio::time::sleep(Duration::from_secs(duration_secs)).await;
    let _ = stop_tx.send(true);

    // Wait for all workers to finish
    for h in handles {
        let _ = h.await;
    }

    // Drain all buffered samples
    let mut samples = Vec::new();
    while let Ok(sample) = rx.try_recv() {
        samples.push(sample);
    }

    let report = aggregate(samples, &scenario, concurrency, duration_secs);

    print_report(&report);
    if let Some(ref path) = output {
        write_json(&report, path)?;
    }

    Ok(report)
}
