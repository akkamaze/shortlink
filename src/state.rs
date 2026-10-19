use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use deadpool_postgres::Pool;

use crate::{auth::sign_in_providers::SignInProviders, config::Config, crypto::DataKeys};

#[derive(Clone)]
pub struct AppState {
    pub db: Pool,
    pub cookie_key: Key,
    pub secure_cookies: bool,
    pub keys: Arc<DataKeys>,
    pub providers: Arc<SignInProviders>,
}

impl AppState {
    pub fn new(config: &Config, db: Pool, providers: SignInProviders) -> Self {
        Self {
            db,
            cookie_key: config.cookie_key.clone(),
            secure_cookies: config.https(),
            keys: Arc::new(config.data_keys.clone()),
            providers: Arc::new(providers),
        }
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
