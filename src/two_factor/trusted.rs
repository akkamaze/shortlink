use anyhow::Context;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use deadpool_postgres::Pool;
use time::Duration;
use uuid::Uuid;

use crate::crypto::opaque_token::{OpaqueToken, hash_of};

pub const TRUST_COOKIE: &str = "sl_trust";
const TRUST_DAYS: i64 = 30;

/// The secret a trusted browser keeps. Only its hash is stored, so a
/// database leak cannot be turned into a cookie that skips the code.
pub struct TrustToken(OpaqueToken);

impl TrustToken {
    pub fn into_cookie(self, secure: bool) -> Cookie<'static> {
        Cookie::build((TRUST_COOKIE, self.0.raw))
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(Duration::days(TRUST_DAYS))
            .build()
    }
}

pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build(TRUST_COOKIE).path("/").build()
}

/// Remembers this browser for the user for 30 days.
pub async fn trust(db: &Pool, user_id: Uuid) -> anyhow::Result<TrustToken> {
    let token = OpaqueToken::generate();

    let client = db.get().await.context("no database connection")?;
    client
        .execute(
            "INSERT INTO trusted_devices (token_hash, user_id, expires_at)
             VALUES ($1, $2, now() + make_interval(days => $3))",
            &[&token.hash, &user_id, &i32::try_from(TRUST_DAYS)?],
        )
        .await
        .context("cannot remember the trusted device")?;

    Ok(TrustToken(token))
}

/// Whether this browser's cookie was trusted by this user and has not run
/// out. A cookie trusted by someone else counts for nothing.
pub async fn is_trusted(db: &Pool, jar: &CookieJar, user_id: Uuid) -> anyhow::Result<bool> {
    let Some(hash) = jar
        .get(TRUST_COOKIE)
        .and_then(|cookie| hash_of(cookie.value()))
    else {
        return Ok(false);
    };

    let client = db.get().await.context("no database connection")?;
    let row = client
        .query_opt(
            "SELECT 1 FROM trusted_devices
             WHERE token_hash = $1 AND user_id = $2 AND expires_at > now()",
            &[&hash, &user_id],
        )
        .await
        .context("cannot check the trusted device")?;

    Ok(row.is_some())
}

/// Every browser of this user asks for a code again.
pub async fn forget_all(db: &Pool, user_id: Uuid) -> anyhow::Result<u64> {
    let client = db.get().await.context("no database connection")?;

    client
        .execute(
            "DELETE FROM trusted_devices WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .context("cannot forget the trusted devices")
}

pub async fn delete_expired(db: &Pool) -> anyhow::Result<u64> {
    let client = db.get().await.context("no database connection")?;

    client
        .execute("DELETE FROM trusted_devices WHERE expires_at <= now()", &[])
        .await
        .context("cannot delete expired trusted devices")
}
