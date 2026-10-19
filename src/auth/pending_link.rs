use axum_extra::extract::cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use time::Duration;
use uuid::Uuid;

use super::accounts::VerifiedIdentity;

pub const LINK_COOKIE: &str = "sl_link";
const LINK_MINUTES: i64 = 10;

/// A sign-in that stopped because its email belongs to another account. It
/// waits in an encrypted cookie until that account's owner confirms, picks a
/// separate account, or ten minutes pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLink {
    pub holder: Uuid,
    pub identity: VerifiedIdentity,
}

impl PendingLink {
    pub fn decode(value: &str) -> Option<Self> {
        serde_json::from_str(value).ok()
    }

    pub fn into_cookie(self, secure: bool) -> Cookie<'static> {
        let value = serde_json::to_string(&self).expect("a pending link always serializes");

        Cookie::build((LINK_COOKIE, value))
            .path("/")
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .max_age(Duration::minutes(LINK_MINUTES))
            .build()
    }

    pub fn removal_cookie() -> Cookie<'static> {
        Cookie::build(LINK_COOKIE).path("/").build()
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::PendingLink;
    use crate::auth::{
        accounts::{ProviderEmail, VerifiedIdentity},
        provider::Provider,
    };

    #[test]
    fn round_trips_through_the_cookie_value() {
        let pending = PendingLink {
            holder: Uuid::new_v4(),
            identity: VerifiedIdentity {
                provider: Provider::Google,
                subject: "123".to_owned(),
                email: Some(ProviderEmail {
                    address: "ann@example.com".to_owned(),
                    verified: true,
                }),
                display_name: Some("Ann".to_owned()),
                picture: None,
            },
        };

        let cookie = pending.clone().into_cookie(true);

        assert_eq!(PendingLink::decode(cookie.value()), Some(pending));
        assert_eq!(PendingLink::decode("{}"), None);
    }
}
