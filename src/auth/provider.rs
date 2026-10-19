use openidconnect::core::CoreJwsSigningAlgorithm;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Sign-in providers the app knows about. Adding one means adding a variant
/// here, an icon template and its OIDC settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    Line,
}

impl Provider {
    pub const ALL: [Provider; 2] = [Provider::Google, Provider::Line];

    pub fn slug(self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::Line => "line",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Provider::Google => "Google",
            Provider::Line => "LINE",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.slug() == slug)
    }

    /// LINE's ID token has no `email_verified`, so its email is never trusted
    /// and not even requested.
    pub fn vouches_for_email(self) -> bool {
        match self {
            Provider::Google => true,
            Provider::Line => false,
        }
    }

    /// LINE signs web-login ID tokens with HS256 and the channel secret, yet
    /// its discovery lists only ES256.
    pub fn unlisted_id_token_algs(self) -> &'static [CoreJwsSigningAlgorithm] {
        match self {
            Provider::Google => &[],
            Provider::Line => &[CoreJwsSigningAlgorithm::HmacSha256],
        }
    }

    pub fn scopes(self) -> &'static [&'static str] {
        match self {
            Provider::Google => &["email", "profile"],
            Provider::Line => &["profile"],
        }
    }
}

impl Serialize for Provider {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.slug())
    }
}

impl<'de> Deserialize<'de> for Provider {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let slug = String::deserialize(deserializer)?;
        Provider::from_slug(&slug).ok_or_else(|| D::Error::custom("unknown provider"))
    }
}
