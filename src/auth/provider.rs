/// Sign-in providers the app knows about. Adding Apple or LINE means adding a
/// variant here, an icon template and its OIDC settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    Google,
}

impl Provider {
    pub const ALL: [Provider; 1] = [Provider::Google];

    pub fn slug(self) -> &'static str {
        match self {
            Provider::Google => "google",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Provider::Google => "Google",
        }
    }

    pub fn from_slug(slug: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.slug() == slug)
    }
}
