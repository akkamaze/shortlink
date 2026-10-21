use anyhow::Context;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use deadpool_postgres::Pool;
use time::Duration;
use uuid::Uuid;

use super::picture::PictureUrl;
use crate::crypto::{
    DataKeys, Field, OpenError,
    opaque_token::{OpaqueToken, hash_of},
};

pub const SESSION_COOKIE: &str = "sl_session";
const SESSION_DAYS: i64 = 30;

/// The raw session secret. Only its hash is stored, so a database leak
/// cannot be replayed as a login.
pub struct SessionToken(OpaqueToken);

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
    pub fn into_cookie(self, secure: bool) -> Cookie<'static> {
        Cookie::build((SESSION_COOKIE, self.0.raw))
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(Duration::days(SESSION_DAYS))
            .build()
    }
}

pub fn removal_cookie() -> Cookie<'static> {
    Cookie::build(SESSION_COOKIE).path("/").build()
}

pub async fn create(db: &Pool, user_id: Uuid) -> anyhow::Result<SessionToken> {
    let token = OpaqueToken::generate();

    let client = db.get().await.context("no database connection")?;
    client
        .execute(
            "INSERT INTO sessions (token_hash, user_id, expires_at)
             VALUES ($1, $2, now() + make_interval(days => $3))",
            &[&token.hash, &user_id, &i32::try_from(SESSION_DAYS)?],
        )
        .await
        .context("cannot store the session")?;

    Ok(SessionToken(token))
}

/// The signed-in person, or `None`. A session also ends here when its
/// profile can no longer be opened, for example after a key change.
pub async fn current_user(
    db: &Pool,
    keys: &DataKeys,
    jar: &CookieJar,
) -> anyhow::Result<Option<CurrentUser>> {
    let Some(hash) = jar.get(SESSION_COOKIE).and_then(|c| hash_of(c.value())) else {
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
    let Some(hash) = jar.get(SESSION_COOKIE).and_then(|c| hash_of(c.value())) else {
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
