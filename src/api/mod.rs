mod auth;
#[cfg(feature = "loadtest")]
mod cdc_test;
mod enroll;
pub mod formations;
mod health;
mod identity;
mod orgs;
mod sinks;
mod tokens;

use axum::Router;
use metrics_exporter_prometheus::PrometheusHandle;
use tower_http::services::{ServeDir, ServeFile};

use crate::cdc::CdcEngine;
use crate::tenant::TenantManager;
use formations::MeshStateRegistry;

/// Install the global Prometheus metrics recorder and return a handle for
/// rendering the /metrics endpoint.  Safe to call multiple times — only the
/// first call installs the recorder; subsequent calls return a clone of the
/// same handle.
pub fn install_prometheus_recorder() -> PrometheusHandle {
    use std::sync::OnceLock;
    static HANDLE: OnceLock<PrometheusHandle> = OnceLock::new();
    HANDLE
        .get_or_init(|| {
            metrics_exporter_prometheus::PrometheusBuilder::new()
                .install_recorder()
                .expect("failed to install Prometheus recorder")
        })
        .clone()
}

pub fn router(
    tenant_mgr: TenantManager,
    cdc_engine: CdcEngine,
    ui_dir: Option<&str>,
    admin_token: Option<String>,
) -> Router {
    router_with_mesh(
        tenant_mgr,
        cdc_engine,
        ui_dir,
        admin_token,
        MeshStateRegistry::new(),
    )
}

pub fn router_with_mesh(
    tenant_mgr: TenantManager,
    cdc_engine: CdcEngine,
    ui_dir: Option<&str>,
    admin_token: Option<String>,
    mesh: MeshStateRegistry,
) -> Router {
    let r = app_authenticated_with_mesh(tenant_mgr.clone(), admin_token, mesh);

    #[cfg(feature = "loadtest")]
    let r = r.nest("/orgs", cdc_test::router(tenant_mgr, cdc_engine));
    #[cfg(not(feature = "loadtest"))]
    let _ = (tenant_mgr, cdc_engine);

    if let Some(dir) = ui_dir {
        let index = format!("{}/index.html", dir);
        r.nest_service(
            "/_",
            ServeDir::new(dir).not_found_service(ServeFile::new(index)),
        )
    } else {
        r
    }
}

/// Build the application router without admin auth (dev/test convenience).
pub fn app(tenant_mgr: TenantManager) -> Router {
    app_authenticated_with_mesh(tenant_mgr, None, MeshStateRegistry::new())
}

/// Build the application router with optional admin token enforcement.
pub fn app_authenticated(tenant_mgr: TenantManager, admin_token: Option<String>) -> Router {
    app_authenticated_with_mesh(tenant_mgr, admin_token, MeshStateRegistry::new())
}

pub fn app_authenticated_with_mesh(
    tenant_mgr: TenantManager,
    admin_token: Option<String>,
    mesh: MeshStateRegistry,
) -> Router {
    let prometheus_handle = install_prometheus_recorder();
    app_with_metrics_and_mesh(tenant_mgr, prometheus_handle, admin_token, mesh)
}

/// Build the application router with an explicit PrometheusHandle.
pub fn app_with_metrics(
    tenant_mgr: TenantManager,
    prometheus_handle: PrometheusHandle,
    admin_token: Option<String>,
) -> Router {
    app_with_metrics_and_mesh(
        tenant_mgr,
        prometheus_handle,
        admin_token,
        MeshStateRegistry::new(),
    )
}

pub fn app_with_metrics_and_mesh(
    tenant_mgr: TenantManager,
    prometheus_handle: PrometheusHandle,
    admin_token: Option<String>,
    mesh: MeshStateRegistry,
) -> Router {
    // Admin routes — protected by bearer token when PEAT_ADMIN_TOKEN is set
    let admin_routes = Router::new()
        .nest("/orgs", orgs::router(tenant_mgr.clone()))
        .nest("/orgs", tokens::router(tenant_mgr.clone()))
        .nest("/orgs", sinks::router(tenant_mgr.clone()))
        .nest("/orgs", identity::router(tenant_mgr.clone()))
        .nest(
            "/orgs",
            formations::router_with_mesh(tenant_mgr.clone(), mesh),
        )
        .layer(axum::middleware::from_fn_with_state(
            admin_token,
            auth::require_admin_token,
        ));

    // Public routes — no auth required
    Router::new()
        .merge(admin_routes)
        .nest("/orgs", enroll::router(tenant_mgr))
        .merge(health::router(prometheus_handle))
}
