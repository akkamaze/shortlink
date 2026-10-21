use deadpool_postgres::Pool;

use crate::{auth::session, two_factor::trusted};

/// Deletes sessions and trusted devices past their expiry, once per period.
/// Each kind is cleaned on its own, so one failing does not stop the other.
pub async fn run_every(db: Pool, period: std::time::Duration) {
    let mut ticker = tokio::time::interval(period);

    loop {
        ticker.tick().await;

        match session::delete_expired(&db).await {
            Ok(removed) => tracing::info!(removed, "expired sessions deleted"),
            Err(error) => tracing::warn!(error = %error, "expired session cleanup failed"),
        }
        match trusted::delete_expired(&db).await {
            Ok(removed) => tracing::info!(removed, "expired trusted devices deleted"),
            Err(error) => tracing::warn!(error = %error, "expired trusted device cleanup failed"),
        }
    }
}
