use std::sync::Arc;

use anyhow::Context;
use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, post},
};
use tower_http::{csrf::CsrfLayer, services::ServeDir, trace::TraceLayer};
use url::Url;

use crate::{auth, links, pages, request_log, security_headers, state::AppState, two_factor};

pub fn router(state: AppState, public_base_url: &Url) -> anyhow::Result<Router> {
    let site_headers = Arc::new(security_headers::site_headers(state.secure_cookies));

    let csrf = CsrfLayer::new()
        .add_trusted_origin(public_base_url.origin().ascii_serialization())
        .context("PUBLIC_BASE_URL is not a valid origin")?;

    Ok(Router::new()
        .route("/", get(|| async { Redirect::to("/app") }))
        .route("/healthz", get(|| async { "ok" }))
        .route("/login", get(pages::login::show))
        .route("/app", get(pages::home::show))
        .route("/auth/{provider}/start", get(auth::routes::start))
        .route("/auth/{provider}/callback", get(auth::routes::callback))
        .route("/logout", post(auth::routes::logout))
        .route(
            "/login/2fa",
            get(pages::two_factor_login::show).post(two_factor::routes::check_at_login),
        )
        .route("/settings", get(pages::settings::show))
        .route("/settings/2fa", get(pages::two_factor_setup::show))
        .route("/settings/2fa/start", post(two_factor::routes::start))
        .route("/settings/2fa/confirm", post(two_factor::routes::confirm))
        .route("/settings/2fa/off", post(two_factor::routes::turn_off))
        .route("/settings/2fa/cancel", post(two_factor::routes::cancel))
        .route(
            "/settings/2fa/recovery-codes",
            post(two_factor::routes::new_recovery_codes),
        )
        .route(
            "/settings/2fa/forget-devices",
            post(two_factor::routes::forget_devices),
        )
        .merge(links::routes::router())
        .nest_service("/static", ServeDir::new("static"))
        .layer(csrf)
        .layer(middleware::from_fn_with_state(
            site_headers,
            security_headers::apply,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_log::request_span))
        .with_state(state))
}
