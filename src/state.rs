use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use deadpool_postgres::Pool;

use crate::{auth::oidc::OidcProviders, config::Config, crypto::DataKeys};

#[derive(Clone)]
pub struct AppState {
    pub db: Pool,
    pub cookie_key: Key,
    pub secure_cookies: bool,
    pub keys: Arc<DataKeys>,
    pub oidc: Arc<OidcProviders>,
}

impl AppState {
    pub fn new(config: &Config, db: Pool, oidc: OidcProviders) -> Self {
        Self {
            db,
            cookie_key: config.cookie_key.clone(),
            secure_cookies: config.https(),
            keys: Arc::new(config.data_keys.clone()),
            oidc: Arc::new(oidc),
        }
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
