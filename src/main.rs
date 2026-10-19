use std::time::Duration;

use anyhow::Context;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use shortlink::{
    app,
    auth::{oidc::OidcProviders, session},
    config::Config,
    db,
    state::AppState,
};

const SESSION_CLEANUP_PERIOD: Duration = Duration::from_hours(1);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .init();

    let config = Config::from_env()?;

    let pool = db::connect_pool(&config.database_url)?;
    tokio::spawn(session::delete_expired_every(
        pool.clone(),
        SESSION_CLEANUP_PERIOD,
    ));

    let oidc = OidcProviders::discover(&config).await?;
    let state = AppState::new(&config, pool, oidc);
    let router = app::router(state, &config.public_base_url)?;

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("cannot listen on {}", config.bind_addr))?;
    tracing::info!(addr = %config.bind_addr, "listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server stopped with an error")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
