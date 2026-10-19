#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();

    let database_url = shortlink::config::secret("MIGRATION_DATABASE_URL")?;
    shortlink::db::run_migrations(&database_url).await
}
