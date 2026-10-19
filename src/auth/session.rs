use anyhow::Context;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use time::Duration;
use uuid::Uuid;

use super::picture::PictureUrl;
use crate::crypto::{DataKeys, Field, OpenError};

pub const SESSION_COOKIE: &str = "sl_session";
const SESSION_DAYS: i64 = 30;
const TOKEN_BYTES: usize = 32;

/// The raw session secret. Only its SHA-256 hash is stored, so a database
/// leak cannot be replayed as a login.
pub struct SessionToken {
    raw: String,
    hash: Vec<u8>,
}

pub struct CurrentUser {
    pub id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub picture: Option<PictureUrl>,
}

struct SealedProfile {
    email: Option<Vec<u8>>,
    display_name: Option<Vec<u8>>,
    picture: Option<Vec<u8>>,
}

impl SessionToken {
    fn generate() -> Self {
        let mut bytes = [0u8; TOKEN_BYTES];
        rand::fill(&mut bytes);

        Self {
            raw: URL_SAFE_NO_PAD.encode(bytes),
            hash: Sha256::digest(bytes).to_vec(),
        }
    }

    pub fn into_cookie(self, secure: bool) -> Cookie<'static> {
        Cookie::build((SESSION_COOKIE, self.raw))
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(Duration::days(SESSION_DAYS))
            .build()
    }
}

/// `None` for anything that is not exactly 32 bytes of URL-safe base64, so
/// junk cookies never reach the database.
fn token_hash(raw: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(raw).ok()?;
    (bytes.len() == TOKEN_BYTES).then(|| Sha256::digest(&bytes).to_vec())
}

pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE).path("/").build()
}

pub async fn create(db: &Pool, user_id: Uuid) -> anyhow::Result<SessionToken> {
    let token = SessionToken::generate();

    let client = db.get().await.context("no database connection")?;
    client
        .execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at)
             VALUES ($1, $2, now() + make_interval(days => $3))",
            &[&token.hash, &user_id, &i32::try_from(SESSION_DAYS)?],
        )
        .await
        .context("cannot store the session")?;

    Ok(token)
}

/// The signed-in person, or `None`. A session also ends here when its
/// profile can no longer be opened, for example after a key change.
pub async fn current_user(
    db: &Pool,
    keys: &DataKeys,
    jar: &CookieJar,
) -> anyhow::Result<Option<CurrentUser>> {
    let Some(hash) = jar.get(SESSION_COOKIE).and_then(|c| token_hash(c.value())) else {
        return Ok(None);
    };

    let client = db.get().await.context("no database connection")?;
    let row = client
        .query_opt(
            "SELECT u.id, u.email_sealed, u.display_name_sealed, u.picture_sealed
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = $1 AND s.expires_at > now()",
            &[&hash],
        )
        .await
        .context("cannot look up the session")?;

    let Some(row) = row else {
        return Ok(None);
    };

    let id: Uuid = row.get(0);
    let sealed = SealedProfile {
        email: row.get(1),
        display_name: row.get(2),
        picture: row.get(3),
    };

    let Ok(user) = open_profile(keys, id, &sealed) else {
        tracing::warn!("session profile cannot be opened; signing the session out");
        end_session(&client, &hash).await?;
        return Ok(None);
    };

    Ok(Some(user))
}

fn open_profile(
    keys: &DataKeys,
    id: Uuid,
    sealed: &SealedProfile,
) -> Result<CurrentUser, OpenError> {
    let open = |value: &Option<Vec<u8>>, field| {
        value
            .as_deref()
            .map(|value| keys.open(value, field, id))
            .transpose()
    };

    Ok(CurrentUser {
        id,
        email: open(&sealed.email, Field::UserEmail)?,
        display_name: open(&sealed.display_name, Field::UserDisplayName)?,
        picture: open(&sealed.picture, Field::UserPicture)?
            .and_then(|picture| PictureUrl::parse(&picture)),
    })
}

async fn end_session(client: &deadpool_postgres::Object, hash: &[u8]) -> anyhow::Result<()> {
    client
        .execute("DELETE FROM sessions WHERE token_hash = $1", &[&hash])
        .await
        .context("cannot end the session")?;
    Ok(())
}

pub async fn delete(db: &Pool, jar: &CookieJar) -> anyhow::Result<()> {
    let Some(hash) = jar.get(SESSION_COOKIE).and_then(|c| token_hash(c.value())) else {
        return Ok(());
    };

    let client = db.get().await.context("no database connection")?;
    client
        .execute("DELETE FROM sessions WHERE token_hash = $1", &[&hash])
        .await
        .context("cannot delete the session")?;

    Ok(())
}

/// Removes sessions past their expiry. Safe to run any number of times.
pub async fn delete_expired(db: &Pool) -> anyhow::Result<u64> {
    let client = db.get().await.context("no database connection")?;

    client
        .execute("DELETE FROM sessions WHERE expires_at <= now()", &[])
        .await
        .context("cannot delete expired sessions")
}

pub async fn delete_expired_every(db: Pool, period: std::time::Duration) {
    let mut ticker = tokio::time::interval(period);

    loop {
        ticker.tick().await;

        match delete_expired(&db).await {
            Ok(removed) => tracing::info!(removed, "expired sessions deleted"),
            Err(error) => tracing::warn!(error = %error, "expired session cleanup failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionToken, token_hash};

    #[test]
    fn cookie_value_hashes_to_the_stored_hash() {
        let first = SessionToken::generate();
        let second = SessionToken::generate();

        assert_ne!(first.raw, second.raw);
        assert_eq!(token_hash(&first.raw), Some(first.hash));
    }

    #[test]
    fn malformed_tokens_are_rejected_before_the_database() {
        assert_eq!(token_hash(""), None);
        assert_eq!(token_hash("not base64 !"), None);
        assert_eq!(token_hash("c2hvcnQ"), None);
    }
}
