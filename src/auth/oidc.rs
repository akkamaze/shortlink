use anyhow::Context;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreJwsSigningAlgorithm, CoreProviderMetadata},
    reqwest,
    url::Url,
};

use super::{
    accounts::{ProviderEmail, VerifiedIdentity},
    error::AuthError,
    pending_login::PendingLogin,
    picture::PictureUrl,
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

/// OIDC clients built from each configured provider's discovery document at
/// start-up.
pub struct OidcProviders {
    http: reqwest::Client,
    clients: Vec<ConfiguredClient>,
}

struct ConfiguredClient {
    provider: Provider,
    client: DiscoveredClient,
    id_token_algs: Vec<CoreJwsSigningAlgorithm>,
}

impl OidcProviders {
    pub async fn discover(config: &Config) -> anyhow::Result<Self> {
        let http = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("cannot build the HTTP client")?;

        let mut clients = Vec::new();
        for settings in &config.providers {
            let redirect = callback_url(&config.public_base_url, settings.provider)?;
            clients.push(discover_client(&http, settings, redirect).await?);
        }

        Ok(Self { http, clients })
    }

    fn configured(&self, provider: Provider) -> Option<&ConfiguredClient> {
        self.clients
            .iter()
            .find(|configured| configured.provider == provider)
    }

    /// Configured providers, in the order buttons are shown.
    pub fn enabled(&self) -> Vec<Provider> {
        Provider::ALL
            .into_iter()
            .filter(|provider| self.configured(*provider).is_some())
            .collect()
    }

    /// The provider URL to send the browser to, and what it must bring back.
    /// `None` when the provider is not configured.
    pub fn begin(&self, provider: Provider) -> Option<(Url, PendingLogin)> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut request = self.configured(provider)?.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in provider.scopes() {
            request = request.add_scope(Scope::new((*scope).to_owned()));
        }
        let (url, state, nonce) = request.set_pkce_challenge(pkce_challenge).url();

        let pending = PendingLogin {
            provider,
            state: state.into_secret(),
            nonce: nonce.secret().clone(),
            pkce_verifier: pkce_verifier.into_secret(),
        };
        Some((url, pending))
    }

    /// Exchanges the code and checks the ID token's signature, issuer,
    /// audience, expiry and nonce.
    pub async fn finish(
        &self,
        pending: PendingLogin,
        code: String,
    ) -> Result<VerifiedIdentity, AuthError> {
        let configured = self
            .configured(pending.provider)
            .ok_or(AuthError::Expired)?;
        let client = &configured.client;

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
        let verifier = client
            .id_token_verifier()
            .set_allowed_algs(configured.id_token_algs.iter().cloned());
        let claims = id_token
            .claims(&verifier, &Nonce::new(pending.nonce))
            .map_err(|error| AuthError::Provider(describe_claims_error(&error).to_owned()))?;

        let email = if pending.provider.vouches_for_email() {
            if claims.email_verified() != Some(true) {
                return Err(AuthError::EmailNotVerified);
            }
            let email = claims.email().ok_or(AuthError::EmailNotVerified)?;
            Some(ProviderEmail {
                address: email.as_str().to_owned(),
                verified: true,
            })
        } else {
            None
        };

        Ok(VerifiedIdentity {
            provider: pending.provider,
            subject: claims.subject().as_str().to_owned(),
            email,
            display_name: claims
                .name()
                .and_then(|name| name.get(None))
                .map(|name| name.as_str().to_owned()),
            picture: claims
                .picture()
                .and_then(|picture| picture.get(None))
                .and_then(|picture| PictureUrl::parse(picture.as_str())),
        })
    }
}

async fn discover_client(
    http: &reqwest::Client,
    settings: &OidcProviderConfig,
    redirect: RedirectUrl,
) -> anyhow::Result<ConfiguredClient> {
    let issuer = IssuerUrl::new(settings.issuer_url.clone()).context("invalid issuer URL")?;

    let metadata = CoreProviderMetadata::discover_async(issuer, http)
        .await
        .with_context(|| format!("cannot read OIDC discovery from {}", settings.issuer_url))?;

    let id_token_algs = accepted_id_token_algs(
        settings.provider,
        metadata.id_token_signing_alg_values_supported(),
    );
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(settings.client_id.clone()),
        Some(ClientSecret::new(settings.client_secret.clone())),
    )
    .set_redirect_uri(redirect);

    Ok(ConfiguredClient {
        provider: settings.provider,
        client,
        id_token_algs,
    })
}

/// What discovery lists, plus what the provider signs with but leaves out.
/// LINE listing `[ES256]` gives `[ES256, HS256]`.
fn accepted_id_token_algs(
    provider: Provider,
    discovered: &[CoreJwsSigningAlgorithm],
) -> Vec<CoreJwsSigningAlgorithm> {
    let mut algs = discovered.to_vec();

    for alg in provider.unlisted_id_token_algs() {
        if !algs.contains(alg) {
            algs.push(alg.clone());
        }
    }

    algs
}

fn callback_url(base: &Url, provider: Provider) -> anyhow::Result<RedirectUrl> {
    let url = base
        .join(&format!("/auth/{}/callback", provider.slug()))
        .context("cannot build the callback URL")?;

    Ok(RedirectUrl::from_url(url))
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use openidconnect::{
        Audience, ClientId, ClientSecret, EmptyAdditionalClaims, IssuerUrl, Nonce, StandardClaims,
        SubjectIdentifier,
        core::{
            CoreHmacKey, CoreIdToken, CoreIdTokenClaims, CoreIdTokenVerifier, CoreJsonWebKeySet,
            CoreJwsSigningAlgorithm::{self, EcdsaP256Sha256, HmacSha256, RsaSsaPkcs1V15Sha256},
        },
    };

    use super::accepted_id_token_algs;
    use crate::auth::provider::Provider;

    const ISSUER: &str = "https://access.line.me";
    const CHANNEL_ID: &str = "1234567890";
    const CHANNEL_SECRET: &str = "channel-secret";

    fn web_login_id_token(nonce: &Nonce) -> CoreIdToken {
        let claims = CoreIdTokenClaims::new(
            IssuerUrl::new(ISSUER.to_owned()).unwrap(),
            vec![Audience::new(CHANNEL_ID.to_owned())],
            Utc::now() + Duration::minutes(5),
            Utc::now(),
            StandardClaims::new(SubjectIdentifier::new("U1234".to_owned())),
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(nonce.clone()));

        CoreIdToken::new(
            claims,
            &CoreHmacKey::new(CHANNEL_SECRET.as_bytes()),
            HmacSha256,
            None,
            None,
        )
        .unwrap()
    }

    fn verifier(
        secret: &str,
        provider: Provider,
        discovered: &[CoreJwsSigningAlgorithm],
    ) -> CoreIdTokenVerifier<'static> {
        CoreIdTokenVerifier::new_confidential_client(
            ClientId::new(CHANNEL_ID.to_owned()),
            ClientSecret::new(secret.to_owned()),
            IssuerUrl::new(ISSUER.to_owned()).unwrap(),
            CoreJsonWebKeySet::new(Vec::new()),
        )
        .set_allowed_algs(accepted_id_token_algs(provider, discovered))
    }

    #[test]
    fn line_web_login_tokens_signed_with_the_channel_secret_verify() {
        let nonce = Nonce::new("n-1".to_owned());
        let token = web_login_id_token(&nonce);

        let line = verifier(CHANNEL_SECRET, Provider::Line, &[EcdsaP256Sha256]);
        let claims = token.claims(&line, &nonce).unwrap();

        assert_eq!(claims.subject().as_str(), "U1234");
    }

    #[test]
    fn line_tokens_signed_with_another_secret_are_refused() {
        let nonce = Nonce::new("n-1".to_owned());
        let token = web_login_id_token(&nonce);

        let line = verifier("wrong-secret", Provider::Line, &[EcdsaP256Sha256]);

        assert!(token.claims(&line, &nonce).is_err());
    }

    #[test]
    fn google_keeps_only_what_discovery_lists() {
        let nonce = Nonce::new("n-1".to_owned());
        let token = web_login_id_token(&nonce);

        let google = verifier(CHANNEL_SECRET, Provider::Google, &[RsaSsaPkcs1V15Sha256]);

        assert!(
            token.claims(&google, &nonce).is_err(),
            "no HS256 for Google"
        );
    }

    #[test]
    fn line_still_accepts_what_its_discovery_lists() {
        assert_eq!(
            accepted_id_token_algs(Provider::Line, &[RsaSsaPkcs1V15Sha256]),
            [RsaSsaPkcs1V15Sha256, HmacSha256],
            "the mock provider signs RS256"
        );
        assert_eq!(
            accepted_id_token_algs(Provider::Line, &[EcdsaP256Sha256, HmacSha256]),
            [EcdsaP256Sha256, HmacSha256]
        );
    }
}
