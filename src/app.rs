use std::sync::Arc;

use axum::{Router, middleware, response::Redirect, routing::get};
use tower_http::{services::ServeDir, trace::TraceLayer};

use crate::{pages, request_log, security_headers};

pub fn router(https: bool) -> Router {
    let site_headers = Arc::new(security_headers::site_headers(https));

    Router::new()
        .route("/", get(|| async { Redirect::to("/login") }))
        .route("/healthz", get(|| async { "ok" }))
        .route("/login", get(pages::login::show))
        .nest_service("/static", ServeDir::new("static"))
        .layer(middleware::from_fn_with_state(
            site_headers,
            security_headers::apply,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_log::request_span))
}
