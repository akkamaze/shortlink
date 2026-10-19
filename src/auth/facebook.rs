use std::fmt::Write;

use anyhow::Context;
use hmac::{Hmac, KeyInit, Mac};
use openidconnect::{CsrfToken, reqwest, url::Url};
use serde::Deserialize;
use sha2::Sha256;

use super::{
    accounts::{ProviderEmail, VerifiedIdentity},
    error::AuthError,
    oidc::callback_url,
    pending_login::{LoginProof, PendingLogin},
    picture::PictureUrl,
    provider::Provider,
};
use crate::config::FacebookConfig;

/// Facebook Login for the web: an OAuth code exchange, then the Graph API's
/// `/me` for the profile. There is no signed ID token, so the profile is
/// trusted because it comes straight from Graph with our app's token.
pub struct FacebookClient {
    http: reqwest::Client,
    settings: FacebookConfig,
    redirect: Url,
}

#[derive(Deserialize)]
struct AccessToken {
    access_token: String,
}

#[derive(Deserialize)]
struct Me {
    id: String,
    name: Option<String>,
    email: Option<String>,
    picture: Option<Picture>,
}

#[derive(Deserialize)]
struct Picture {
    data: PictureData,
}

#[derive(Deserialize)]
struct PictureData {
    url: String,
    #[serde(default)]
    is_silhouette: bool,
}

impl FacebookClient {
    pub fn new(
        http: reqwest::Client,
        settings: FacebookConfig,
        public_base_url: &Url,
    ) -> anyhow::Result<Self> {
        let redirect = callback_url(public_base_url, Provider::Facebook)?
            .url()
            .clone();

        Ok(Self {
            http,
            settings,
            redirect,
        })
    }

    pub fn begin(&self) -> (Url, PendingLogin) {
        let state = CsrfToken::new_random().into_secret();

        let mut url = self.settings.dialog_url.clone();
        url.query_pairs_mut()
            .append_pair("client_id", &self.settings.client_id)
            .append_pair("redirect_uri", self.redirect.as_str())
            .append_pair("state", &state)
            .append_pair("response_type", "code")
            .append_pair("scope", &Provider::Facebook.scopes().join(","));

        let pending = PendingLogin {
            provider: Provider::Facebook,
            state,
            proof: LoginProof::StateOnly,
        };
        (url, pending)
    }

    pub async fn finish(&self, code: String) -> Result<VerifiedIdentity, AuthError> {
        let token = self.exchange(&code).await?;
        let me = self.me(&token).await?;

        Ok(identity_from(me))
    }

    async fn exchange(&self, code: &str) -> Result<String, AuthError> {
        let mut url = self.graph("oauth/access_token")?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.settings.client_id)
            .append_pair("redirect_uri", self.redirect.as_str())
            .append_pair("client_secret", &self.settings.client_secret)
            .append_pair("code", code);

        let token: AccessToken = self.get_json(url, "code exchange").await?;
        Ok(token.access_token)
    }

    async fn me(&self, access_token: &str) -> Result<Me, AuthError> {
        let mut url = self.graph("me")?;
        url.query_pairs_mut()
            .append_pair("fields", "id,name,email,picture.width(96).height(96)")
            .append_pair("access_token", access_token)
            .append_pair(
                "appsecret_proof",
                &appsecret_proof(access_token, &self.settings.client_secret),
            );

        self.get_json(url, "profile request").await
    }

    fn graph(&self, path: &str) -> Result<Url, AuthError> {
        self.settings
            .graph_url
            .join(path)
            .context("FACEBOOK_GRAPH_URL cannot take a path")
            .map_err(AuthError::Internal)
    }

    /// Error bodies and URLs carry tokens and secrets, so only `step` and the
    /// status reach the log.
    async fn get_json<T: for<'de> Deserialize<'de>>(
        &self,
        url: Url,
        step: &str,
    ) -> Result<T, AuthError> {
        let response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| AuthError::Provider(format!("Facebook {step} did not respond")))?;

        let status = response.status();
        if !status.is_success() {
            return Err(AuthError::Provider(format!(
                "Facebook {step} failed with {status}"
            )));
        }

        let body = response
            .bytes()
            .await
            .map_err(|_| AuthError::Provider(format!("Facebook {step} body was cut off")))?;
        serde_json::from_slice(&body)
            .map_err(|_| AuthError::Provider(format!("Facebook {step} sent an unexpected body")))
    }
}

/// Graph's proof that a call comes from the app that owns the token:
/// lowercase hex of HMAC-SHA256 over the token, keyed by the app secret.
fn appsecret_proof(access_token: &str, app_secret: &str) -> String {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(app_secret.as_bytes()).expect("HMAC takes any key length");
    mac.update(access_token.as_bytes());

    mac.finalize()
        .into_bytes()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

/// A default silhouette is no picture; the page shows an initial instead.
fn identity_from(me: Me) -> VerifiedIdentity {
    VerifiedIdentity {
        provider: Provider::Facebook,
        subject: me.id,
        email: me.email.map(|address| ProviderEmail {
            address,
            verified: false,
        }),
        display_name: me.name,
        picture: me
            .picture
            .filter(|picture| !picture.data.is_silhouette)
            .and_then(|picture| PictureUrl::parse(&picture.data.url)),
    }
}

#[cfg(test)]
mod tests {
    use super::{Me, appsecret_proof, identity_from};

    #[test]
    fn appsecret_proof_is_hex_hmac_sha256_of_the_token() {
        // printf 'token' | openssl dgst -sha256 -hmac 'secret'
        assert_eq!(
            appsecret_proof("token", "secret"),
            "e941110e3d2bfe82621f0e3e1434730d7305d106c5f68c87165d0b27a4611a4a"
        );
    }

    #[test]
    fn a_facebook_email_is_never_treated_as_verified() {
        let me: Me = serde_json::from_str(
            r#"{"id":"42","name":"Ann","email":"ann@example.com",
                "picture":{"data":{"url":"https://platform-lookaside.fbsbx.com/p?asid=42","is_silhouette":false}}}"#,
        )
        .unwrap();

        let identity = identity_from(me);

        assert_eq!(identity.subject, "42");
        assert!(!identity.email.unwrap().verified);
        assert!(identity.picture.is_some());
    }

    #[test]
    fn a_silhouette_or_a_foreign_host_gives_no_picture() {
        for picture in [
            r#"{"data":{"url":"https://platform-lookaside.fbsbx.com/p","is_silhouette":true}}"#,
            r#"{"data":{"url":"https://evil.example/p.png","is_silhouette":false}}"#,
        ] {
            let me: Me =
                serde_json::from_str(&format!(r#"{{"id":"42","picture":{picture}}}"#)).unwrap();

            assert!(identity_from(me).picture.is_none(), "{picture}");
        }
    }
}
