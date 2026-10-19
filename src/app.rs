use axum::{Router, routing::get};
use tower_http::trace::TraceLayer;

use crate::request_log;

pub fn router() -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .layer(TraceLayer::new_for_http().make_span_with(request_log::request_span))
}
