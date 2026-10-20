use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;
use uuid::Uuid;

pub const PENDING_COOKIE: &str = "sl_2fa";
const PENDING_MINUTES: i64 = 5;
const PATH: &str = "/login/2fa";

/// A sign-in that passed the provider and now waits for the second factor.
/// It lives in an encrypted cookie, so it cannot be forged or read, and
/// carries its own deadline because a browser may ignore `Max-Age`.
#[derive(Debug, PartialEq, Eq)]
pub struct PendingSecondFactor {
    pub user_id: Uuid,
    expires_unix: u64,
}

impl PendingSecondFactor {
    pub fn new(user_id: Uuid, now_unix: u64) -> Self {
        Self {
            user_id,
            expires_unix: now_unix + PENDING_MINUTES.unsigned_abs() * 60,
        }
    }

    /// `None` when the value is not ours or its five minutes are over.
    pub fn decode(value: &str, now_unix: u64) -> Option<Self> {
        let (user_id, expires) = value.split_once('.')?;
        let pending = Self {
            user_id: Uuid::parse_str(user_id).ok()?,
            expires_unix: expires.parse().ok()?,
        };

        (now_unix < pending.expires_unix).then_some(pending)
    }

    pub fn into_cookie(self, secure: bool) -> Cookie<'static> {
        Cookie::build((
            PENDING_COOKIE,
            format!("{}.{}", self.user_id, self.expires_unix),
        ))
        .path(PATH)
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(Duration::minutes(PENDING_MINUTES))
        .build()
    }

    pub fn removal_cookie() -> Cookie<'static> {
        Cookie::build(PENDING_COOKIE).path(PATH).build()
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::PendingSecondFactor;

    #[test]
    fn round_trips_until_five_minutes_pass() {
        let user = Uuid::new_v4();
        let cookie = PendingSecondFactor::new(user, 1_000).into_cookie(true);

        assert_eq!(
            PendingSecondFactor::decode(cookie.value(), 1_299).map(|pending| pending.user_id),
            Some(user)
        );
        assert_eq!(PendingSecondFactor::decode(cookie.value(), 1_300), None);
    }

    #[test]
    fn refuses_values_it_did_not_make() {
        assert_eq!(
            PendingSecondFactor::decode("not-a-uuid.9999999999", 0),
            None
        );
        assert_eq!(
            PendingSecondFactor::decode(&Uuid::new_v4().to_string(), 0),
            None
        );
    }
}
