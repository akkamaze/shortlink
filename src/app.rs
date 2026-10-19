use std::sync::Arc;

use anyhow::Context;
use axum::{
    Router, middleware,
    response::Redirect,
    routing::{get, post},
};
use tower_http::{csrf::CsrfLayer, services::ServeDir, trace::TraceLayer};
use url::Url;

use crate::{auth, links, pages, request_log, security_headers, state::AppState};

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
