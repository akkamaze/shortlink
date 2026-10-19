use axum_extra::extract::cookie::{Cookie, SameSite};
use time::Duration;

use super::provider::Provider;

pub const LOGIN_COOKIE: &str = "sl_login";
const LOGIN_MINUTES: i64 = 10;

/// What the browser must bring back from the provider to finish a sign-in.
/// It travels in an encrypted cookie, so nothing is stored server-side
/// before the user is known.
#[derive(Debug, PartialEq, Eq)]
pub struct PendingLogin {
    pub provider: Provider,
    pub state: String,
    pub nonce: String,
    pub pkce_verifier: String,
}

impl PendingLogin {
    /// `google.<state>.<nonce>.<verifier>`; the three values are URL-safe
    /// base64 and never contain a dot.
    fn encode(&self) -> String {
        [
            self.provider.slug(),
            &self.state,
            &self.nonce,
            &self.pkce_verifier,
        ]
        .join(".")
    }

    pub fn decode(value: &str) -> Option<Self> {
        let mut parts = value.split('.');
        let pending = Self {
            provider: Provider::from_slug(parts.next()?)?,
            state: parts.next()?.to_owned(),
            nonce: parts.next()?.to_owned(),
            pkce_verifier: parts.next()?.to_owned(),
        };

        parts.next().is_none().then_some(pending)
    }

    pub fn into_cookie(self, secure: bool) -> Cookie<'static> {
        Cookie::build((LOGIN_COOKIE, self.encode()))
            .path("/auth")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(Duration::minutes(LOGIN_MINUTES))
            .build()
    }

    pub fn removal_cookie() -> Cookie<'static> {
        Cookie::build(LOGIN_COOKIE).path("/auth").build()
    }
}

#[cfg(test)]
mod tests {
    use super::PendingLogin;
    use crate::auth::provider::Provider;

    #[test]
    fn round_trips_through_the_cookie_value() {
        let pending = PendingLogin {
            provider: Provider::Google,
            state: "st-1".to_owned(),
            nonce: "no_2".to_owned(),
            pkce_verifier: "pk3".to_owned(),
        };

        assert_eq!(PendingLogin::decode(&pending.encode()), Some(pending));
    }

    #[test]
    fn rejects_unknown_providers_and_wrong_shapes() {
        assert_eq!(PendingLogin::decode("myspace.a.b.c"), None);
        assert_eq!(PendingLogin::decode("google.a.b"), None);
        assert_eq!(PendingLogin::decode("google.a.b.c.d"), None);
    }
}
