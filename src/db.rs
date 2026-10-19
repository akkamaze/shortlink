use anyhow::Context;
use deadpool_postgres::{Config, Pool, PoolConfig, Runtime};
use tokio_postgres::NoTls;

refinery::embed_migrations!("migrations");

const POOL_SIZE: usize = 16;

pub fn connect_pool(database_url: &str) -> anyhow::Result<Pool> {
    let mut config = Config::new();
    config.url = Some(database_url.to_owned());
    config.pool = Some(PoolConfig::new(POOL_SIZE));

    config
        .create_pool(Some(Runtime::Tokio1), NoTls)
        .context("cannot create the Postgres pool")
}

pub async fn run_migrations(database_url: &str) -> anyhow::Result<()> {
    let (mut client, connection) = tokio_postgres::connect(database_url, NoTls)
        .await
        .context("cannot connect to Postgres for migrations")?;
    tokio::spawn(connection);

    let report = migrations::runner()
        .run_async(&mut client)
        .await
        .context("migration failed")?;

    for migration in report.applied_migrations() {
        tracing::info!(
            name = migration.name(),
            version = migration.version(),
            "applied"
        );
    }
    Ok(())
}
