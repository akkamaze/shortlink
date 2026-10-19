use std::sync::Arc;

use axum::{Router, middleware, routing::get};
use tower_http::trace::TraceLayer;

use crate::{request_log, security_headers};

pub fn router(https: bool) -> Router {
    let site_headers = Arc::new(security_headers::site_headers(https));

    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .layer(middleware::from_fn_with_state(
            site_headers,
            security_headers::apply,
        ))
        .layer(TraceLayer::new_for_http().make_span_with(request_log::request_span))
}
