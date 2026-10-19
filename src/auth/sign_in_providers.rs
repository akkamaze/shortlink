use anyhow::Context;
use openidconnect::{reqwest, url::Url};

use super::{
    accounts::VerifiedIdentity, error::AuthError, facebook::FacebookClient, oidc::OidcProviders,
    pending_login::PendingLogin, provider::Provider,
};
use crate::config::Config;

/// Every configured way to sign in, behind one begin and finish.
pub struct SignInProviders {
    oidc: OidcProviders,
    facebook: Option<FacebookClient>,
}

impl SignInProviders {
    pub async fn connect(config: &Config) -> anyhow::Result<Self> {
        let oidc = OidcProviders::discover(config).await?;

        let facebook = match &config.facebook {
            Some(settings) => Some(FacebookClient::new(
                http_client()?,
                settings.clone(),
                &config.public_base_url,
            )?),
            None => None,
        };

        Ok(Self { oidc, facebook })
    }

    /// Configured providers, in button order.
    pub fn enabled(&self) -> Vec<Provider> {
        let oidc = self.oidc.enabled();

        Provider::ALL
            .into_iter()
            .filter(|provider| match provider {
                Provider::Facebook => self.facebook.is_some(),
                _ => oidc.contains(provider),
            })
            .collect()
    }

    /// `None` when the provider is not configured.
    pub fn begin(&self, provider: Provider) -> Option<(Url, PendingLogin)> {
        match provider {
            Provider::Facebook => self.facebook.as_ref().map(FacebookClient::begin),
            _ => self.oidc.begin(provider),
        }
    }

    pub async fn finish(
        &self,
        pending: PendingLogin,
        code: String,
    ) -> Result<VerifiedIdentity, AuthError> {
        match pending.provider {
            Provider::Facebook => {
                let facebook = self.facebook.as_ref().ok_or(AuthError::Expired)?;
                facebook.finish(code).await
            }
            _ => self.oidc.finish(pending, code).await,
        }
    }
}

fn http_client() -> anyhow::Result<reqwest::Client> {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("cannot build the HTTP client")
}
