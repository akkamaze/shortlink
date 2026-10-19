use anyhow::Context;
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;

use shortlink::{app, config::Config};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,tower_http=debug".into()),
        )
        .init();

    let config = Config::from_env()?;

    let listener = TcpListener::bind(config.bind_addr)
        .await
        .with_context(|| format!("cannot listen on {}", config.bind_addr))?;
    tracing::info!(addr = %config.bind_addr, "listening");

    axum::serve(listener, app::router())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server stopped with an error")
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
