use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::info;
use tracing_subscriber::EnvFilter;

use peat_gateway::{api, cdc, cli, config, tenant};
#[cfg(feature = "mesh-broker-client")]
use peat_gateway::{api::formations::MeshStateRegistry, mesh_ingest::MeshIngestManager};

#[derive(Parser)]
#[command(
    name = "peat-gateway",
    about = "Enterprise control plane for PEAT mesh"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the gateway API server (default)
    Serve,
    /// Encrypt all plaintext genesis records with the configured KEK.
    /// Stop the gateway before running this command.
    MigrateKeys {
        /// Preview what would be migrated without modifying any records
        #[arg(long)]
        dry_run: bool,
    },
    /// Run load tests against a local gateway instance
    #[cfg(feature = "loadtest")]
    LoadTest {
        /// Concurrent workers
        #[arg(long, default_value_t = 10)]
        concurrency: usize,
        /// Test duration in seconds
        #[arg(long, default_value_t = 30)]
        duration: u64,
        /// Scenario: mixed, read-heavy, burst, multi-org
        #[arg(long, default_value = "mixed")]
        scenario: String,
        /// Number of orgs for multi-org scenario
        #[arg(long, default_value_t = 3)]
        orgs: usize,
        /// Write JSON report to file
        #[arg(long)]
        output: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("peat_gateway=info".parse()?))
        .init();

    let args = Cli::parse();
    let config = config::GatewayConfig::from_env()?;

    match args.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(&config).await,
        Command::MigrateKeys { dry_run } => cli::migrate_keys(&config, dry_run).await,
        #[cfg(feature = "loadtest")]
        Command::LoadTest {
            concurrency,
            duration,
            scenario,
            orgs,
            output,
        } => cli::load_test(concurrency, duration, scenario, orgs, output).await,
    }
}

async fn serve(config: &config::GatewayConfig) -> Result<()> {
    info!(
        bind = %config.bind_addr,
        storage = ?config.storage,
        "Starting peat-gateway"
    );

    if config.admin_token.is_none() {
        tracing::warn!("PEAT_ADMIN_TOKEN is not set — admin API is unauthenticated (dev mode)");
    }

    let tenant_mgr = tenant::TenantManager::new(config).await?;
    let cdc_engine = cdc::CdcEngine::new(config, tenant_mgr.clone()).await?;

    #[cfg(feature = "mesh-broker-client")]
    let mesh_registry = {
        let registry = MeshStateRegistry::new();
        if !config.mesh_brokers.is_empty() {
            let manager = MeshIngestManager::new(
                registry.clone(),
                std::time::Duration::from_millis(config.mesh_poll_interval_ms),
            )
            .with_cdc(cdc_engine.clone());
            for mapping in config.mesh_brokers.clone() {
                manager.register_remote_broker(mapping).await;
            }
        }
        registry
    };

    #[cfg(feature = "mesh-broker-client")]
    let app = api::router_with_mesh(
        tenant_mgr,
        cdc_engine,
        config.ui_dir.as_deref(),
        config.admin_token.clone(),
        mesh_registry,
    );

    #[cfg(not(feature = "mesh-broker-client"))]
    let app = api::router(
        tenant_mgr,
        cdc_engine,
        config.ui_dir.as_deref(),
        config.admin_token.clone(),
    );

    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    info!("Listening on {}", config.bind_addr);
    axum::serve(listener, app).await?;

    Ok(())
}
