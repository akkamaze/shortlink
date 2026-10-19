use anyhow::Context;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest,
    url::Url,
};

use super::{
    accounts::VerifiedIdentity,
    error::AuthError,
    pending_login::PendingLogin,
    provider::Provider,
    provider_error::{describe_claims_error, describe_token_error},
};
use crate::config::{Config, OidcProviderConfig};

type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// OIDC clients built from each provider's discovery document at start-up.
pub struct OidcProviders {
    http: reqwest::Client,
    google: DiscoveredClient,
}

impl OidcProviders {
    pub async fn discover(config: &Config) -> anyhow::Result<Self> {
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("cannot build the HTTP client")?;

        let google = discover_client(
            &http,
            &config.google,
            callback_url(&config.public_base_url, Provider::Google)?,
        )
        .await?;

        Ok(Self { http, google })
    }

    fn client(&self, provider: Provider) -> &DiscoveredClient {
        match provider {
            Provider::Google => &self.google,
        }
    }

    /// The provider URL to send the browser to, and what it must bring back.
    pub fn begin(&self, provider: Provider) -> (Url, PendingLogin) {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let (url, state, nonce) = self
            .client(provider)
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .add_scope(Scope::new("email".to_owned()))
            .add_scope(Scope::new("profile".to_owned()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        let pending = PendingLogin {
            provider,
            state: state.into_secret(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.into_secret(),
        };
        (url, pending)
    }

    /// Exchanges the code and checks the ID token's signature, issuer,
    /// audience, expiry and nonce.
    pub async fn finish(
        &self,
        pending: PendingLogin,
        code: String,
    ) -> Result<VerifiedIdentity, AuthError> {
        let client = self.client(pending.provider);

        let tokens = client
            .exchange_code(AuthorizationCode::new(code))
            .map_err(|_| AuthError::Provider("provider has no token endpoint".to_owned()))?
            .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
            .request_async(&self.http)
            .await
            .map_err(|error| AuthError::Provider(describe_token_error(&error).to_owned()))?;

        let id_token = tokens
            .id_token()
            .ok_or_else(|| AuthError::Provider("no ID token in the response".to_owned()))?;
        let claims = id_token
            .claims(&client.id_token_verifier(), &Nonce::new(pending.nonce))
            .map_err(|error| AuthError::Provider(describe_claims_error(&error).to_owned()))?;

        let email = claims
            .email()
            .map(|email| email.as_str().to_owned())
            .ok_or(AuthError::EmailNotVerified)?;
        if claims.email_verified() != Some(true) {
            return Err(AuthError::EmailNotVerified);
        }

        Ok(VerifiedIdentity {
            provider: pending.provider,
            subject: claims.subject().as_str().to_owned(),
            email,
            display_name: claims
                .name()
                .and_then(|name| name.get(None))
                .map(|name| name.as_str().to_owned()),
        })
    }
}

async fn discover_client(
    http: &reqwest::Client,
    settings: &OidcProviderConfig,
    redirect: RedirectUrl,
) -> anyhow::Result<DiscoveredClient> {
    let issuer = IssuerUrl::new(settings.issuer_url.clone()).context("invalid issuer URL")?;

    let metadata = CoreProviderMetadata::discover_async(issuer, http)
        .await
        .with_context(|| format!("cannot read OIDC discovery from {}", settings.issuer_url))?;

    Ok(CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(settings.client_id.clone()),
        Some(ClientSecret::new(settings.client_secret.clone())),
    )
    .set_redirect_uri(redirect))
}

fn callback_url(base: &Url, provider: Provider) -> anyhow::Result<RedirectUrl> {
    let url = base
        .join(&format!("/auth/{}/callback", provider.slug()))
        .context("cannot build the callback URL")?;

    Ok(RedirectUrl::from_url(url))
}
