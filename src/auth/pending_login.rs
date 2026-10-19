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
    pub proof: LoginProof,
}

/// What else ties the callback to this browser. OIDC providers check a nonce
/// in the ID token and a PKCE verifier; Facebook's web login has only `state`.
#[derive(Debug, PartialEq, Eq)]
pub enum LoginProof {
    Oidc {
        nonce: String,
        pkce_verifier: String,
    },
    StateOnly,
}

impl PendingLogin {
    /// `google.<state>.<nonce>.<verifier>` or `facebook.<state>`; the values
    /// are URL-safe base64 and never contain a dot.
    fn encode(&self) -> String {
        let mut parts = vec![self.provider.slug(), self.state.as_str()];
        if let LoginProof::Oidc {
            nonce,
            pkce_verifier,
        } = &self.proof
        {
            parts.extend([nonce.as_str(), pkce_verifier.as_str()]);
        }

        parts.join(".")
    }

    pub fn decode(value: &str) -> Option<Self> {
        let parts: Vec<&str> = value.split('.').collect();
        let provider = Provider::from_slug(parts.first()?)?;

        let proof = match (provider.speaks_oidc(), parts.as_slice()) {
            (true, [_, _, nonce, pkce_verifier]) => LoginProof::Oidc {
                nonce: (*nonce).to_owned(),
                pkce_verifier: (*pkce_verifier).to_owned(),
            },
            (false, [_, _]) => LoginProof::StateOnly,
            _ => return None,
        };

        Some(Self {
            provider,
            state: parts[1].to_owned(),
            proof,
        })
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
    use super::{LoginProof, PendingLogin};
    use crate::auth::provider::Provider;

    #[test]
    fn round_trips_through_the_cookie_value() {
        let oidc = PendingLogin {
            provider: Provider::Google,
            state: "st-1".to_owned(),
            proof: LoginProof::Oidc {
                nonce: "no_2".to_owned(),
                pkce_verifier: "pk3".to_owned(),
            },
        };
        let facebook = PendingLogin {
            provider: Provider::Facebook,
            state: "st-1".to_owned(),
            proof: LoginProof::StateOnly,
        };

        assert_eq!(PendingLogin::decode(&oidc.encode()), Some(oidc));
        assert_eq!(PendingLogin::decode(&facebook.encode()), Some(facebook));
    }

    #[test]
    fn rejects_unknown_providers_and_wrong_shapes() {
        assert_eq!(PendingLogin::decode("myspace.a.b.c"), None);
        assert_eq!(PendingLogin::decode("google.a.b"), None);
        assert_eq!(
            PendingLogin::decode("google.a"),
            None,
            "OIDC needs its nonce"
        );
        assert_eq!(PendingLogin::decode("google.a.b.c.d"), None);
        assert_eq!(PendingLogin::decode("facebook.a.b.c"), None);
    }
}
