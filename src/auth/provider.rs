use openidconnect::core::CoreJwsSigningAlgorithm;

/// Sign-in providers the app knows about, in button order. Adding one means
/// adding a variant here, an icon template and its settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
    Facebook,
    Line,
}

impl Provider {
    pub const ALL: [Provider; 3] = [Provider::Google, Provider::Facebook, Provider::Line];

    pub fn slug(self) -> &'static str {
        match self {
            Provider::Google => "google",
            Provider::Facebook => "facebook",
            Provider::Line => "line",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Provider::Google => "Google",
            Provider::Facebook => "Facebook",
            Provider::Line => "LINE",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.slug() == slug)
    }

    /// Facebook's web login is OAuth with the Graph API, not OIDC.
    pub fn speaks_oidc(self) -> bool {
        !matches!(self, Provider::Facebook)
    }

    /// Only Google's ID token carries a trustworthy `email_verified`, and an
    /// unverified Google email is refused. LINE's email is never requested.
    pub fn vouches_for_email(self) -> bool {
        matches!(self, Provider::Google)
    }

    /// LINE signs web-login ID tokens with HS256 and the channel secret, yet
    /// its discovery lists only ES256.
    pub fn unlisted_id_token_algs(self) -> &'static [CoreJwsSigningAlgorithm] {
        match self {
            Provider::Google | Provider::Facebook => &[],
            Provider::Line => &[CoreJwsSigningAlgorithm::HmacSha256],
        }
    }

    pub fn scopes(self) -> &'static [&'static str] {
        match self {
            Provider::Google => &["email", "profile"],
            Provider::Facebook => &["email", "public_profile"],
            Provider::Line => &["profile"],
        }
    }
}
