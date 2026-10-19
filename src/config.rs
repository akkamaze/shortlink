use std::net::SocketAddr;

use anyhow::{Context, bail};
use axum_extra::extract::cookie::Key;
use url::Url;

use crate::{auth::provider::Provider, crypto::DataKeys};

pub struct Config {
    pub bind_addr: SocketAddr,
    pub public_base_url: Url,
    pub database_url: String,
    pub cookie_key: Key,
    pub data_keys: DataKeys,
    pub providers: Vec<OidcProviderConfig>,
}

pub struct OidcProviderConfig {
    pub provider: Provider,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        let public_base_url = Url::parse(&required("PUBLIC_BASE_URL")?)
            .context("PUBLIC_BASE_URL is not a valid URL")?;

        Ok(Self {
            bind_addr: required("BIND_ADDR")?
                .parse()
                .context("BIND_ADDR must look like 127.0.0.1:3100")?,
            database_url: secret("DATABASE_URL")?,
            cookie_key: cookie_key(&secret("COOKIE_KEY")?)?,
            data_keys: data_keys(&secret("DATA_KEY")?)?,
            providers: providers(&public_base_url)?,
            public_base_url,
        })
    }

    pub fn https(&self) -> bool {
        self.public_base_url.scheme() == "https"
    }
}

/// Google is required. Any other provider is on when its `*_CLIENT_ID` is set,
/// and then needs all of its settings.
fn providers(public_base_url: &Url) -> anyhow::Result<Vec<OidcProviderConfig>> {
    let mut providers = vec![provider_settings(Provider::Google, public_base_url)?];

    for provider in [Provider::Line] {
        if std::env::var(env_name(provider, "CLIENT_ID")).is_ok_and(|id| !id.trim().is_empty()) {
            providers.push(provider_settings(provider, public_base_url)?);
        }
    }

    Ok(providers)
}

fn provider_settings(
    provider: Provider,
    public_base_url: &Url,
) -> anyhow::Result<OidcProviderConfig> {
    let issuer_name = env_name(provider, "ISSUER_URL");
    let issuer_url = required(&issuer_name)?;
    check_issuer(&issuer_name, &issuer_url, public_base_url)?;

    Ok(OidcProviderConfig {
        provider,
        issuer_url,
        client_id: required(&env_name(provider, "CLIENT_ID"))?,
        client_secret: secret(&env_name(provider, "CLIENT_SECRET"))?,
    })
}

/// Catches the callback URL pasted into the issuer setting.
fn check_issuer(name: &str, issuer: &str, public_base_url: &Url) -> anyhow::Result<()> {
    let url = Url::parse(issuer).with_context(|| format!("{name} is not a valid URL"))?;

    if url.origin() == public_base_url.origin() {
        bail!(
            "{name} points at this app ({issuer}). Set it to the provider's issuer, such as \
             https://accounts.google.com or https://access.line.me; the callback URL belongs \
             in the provider's console"
        );
    }

    Ok(())
}

/// `(Provider::Line, "CLIENT_ID")` gives `LINE_CLIENT_ID`.
fn env_name(provider: Provider, setting: &str) -> String {
    format!("{}_{setting}", provider.slug().to_uppercase())
}

fn required(name: &str) -> anyhow::Result<String> {
    match std::env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value.trim().to_owned()),
        _ => bail!("{name} is not set; see .env.example"),
    }
}

/// Reads `NAME_FILE` when set, so Docker secrets can be mounted as files,
/// and falls back to `NAME` for local development.
pub fn secret(name: &str) -> anyhow::Result<String> {
    let file_var = format!("{name}_FILE");
    let Ok(path) = std::env::var(&file_var) else {
        return required(name);
    };

    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {file_var} at {path}"))?;
    match value.trim() {
        "" => bail!("{file_var} points at an empty file"),
        value => Ok(value.to_owned()),
    }
}

fn cookie_key(encoded: &str) -> anyhow::Result<Key> {
    use base64::Engine;

    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("COOKIE_KEY must be base64")?;

    Key::try_from(bytes.as_slice()).context("COOKIE_KEY must decode to at least 64 bytes")
}

fn data_keys(encoded: &str) -> anyhow::Result<DataKeys> {
    use base64::Engine;

    let master = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("DATA_KEY must be base64")?;

    DataKeys::from_master(&master).context("DATA_KEY is too short")
}

#[cfg(test)]
mod tests {
    use url::Url;

    use super::check_issuer;

    #[test]
    fn an_issuer_on_this_app_is_refused_with_the_setting_name() {
        let base = Url::parse("http://localhost:3100").unwrap();

        let error = check_issuer(
            "GOOGLE_ISSUER_URL",
            "http://localhost:3100/auth/google/callback",
            &base,
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("GOOGLE_ISSUER_URL points at this app")
        );
        assert!(check_issuer("GOOGLE_ISSUER_URL", "https://accounts.google.com", &base).is_ok());
        assert!(check_issuer("GOOGLE_ISSUER_URL", "http://localhost:8080/default", &base).is_ok());
    }
}
