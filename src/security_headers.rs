use std::sync::Arc;

use axum::{
    extract::{Request, State},
    http::{HeaderMap, HeaderName, HeaderValue, header},
    middleware::Next,
    response::Response,
};

/// Pages load only our own styles and fonts and run no script. Inline style
/// attributes are allowed because the login card sets per-letter animation
/// delays that way; they cannot execute code.
const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; style-src 'self'; \
     style-src-attr 'unsafe-inline'; font-src 'self'; img-src 'self'; \
     form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

const HSTS: &str = "max-age=31536000; includeSubDomains";

pub fn site_headers(https: bool) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut set = |name: HeaderName, value: &'static str| {
        headers.insert(name, HeaderValue::from_static(value));
    };

    set(header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY);
    set(header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(header::REFERRER_POLICY, "no-referrer");
    set(header::X_FRAME_OPTIONS, "DENY");
    set(
        HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    set(
        HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=(), payment=()",
    );
    if https {
        set(header::STRICT_TRANSPORT_SECURITY, HSTS);
    }

    headers
}

/// Adds the site headers to every response. Pages and redirects are
/// no-store. Static files are no-cache: kept, but revalidated by `ETag` on
/// every use, so a browser never runs new HTML against an old stylesheet.
pub async fn apply(
    State(headers): State<Arc<HeaderMap>>,
    request: Request,
    next: Next,
) -> Response {
    let is_static = request.uri().path().starts_with("/static/");
    let mut response = next.run(request).await;

    let target = response.headers_mut();
    for (name, value) in headers.iter() {
        target.entry(name).or_insert_with(|| value.clone());
    }
    let cache_control = if is_static { "no-cache" } else { "no-store" };
    target.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(cache_control),
    );

    response
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode, header},
        middleware,
        response::{Html, Redirect},
        routing::get,
    };
    use tower::ServiceExt;

    use super::{apply, site_headers};

    async fn response_headers(https: bool, path: &str) -> axum::http::HeaderMap {
        let app = Router::new()
            .route("/page", get(|| async { Html("<p>hi</p>") }))
            .route(
                "/static/file.css",
                get(|| async { ([(header::CONTENT_TYPE, "text/css")], "p{}") }),
            )
            .route(
                "/callback",
                get(|| async { ([(header::SET_COOKIE, "sl_session=x")], Redirect::to("/app")) }),
            )
            .layer(middleware::from_fn_with_state(
                Arc::new(site_headers(https)),
                apply,
            ));

        let response = app
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_ne!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{path} must be routed"
        );

        response.headers().clone()
    }

    #[tokio::test]
    async fn pages_get_the_full_header_set_and_are_never_cached() {
        let headers = response_headers(true, "/page").await;

        let csp = headers[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(!csp.contains("script-src"), "no script source is allowed");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(headers[header::X_FRAME_OPTIONS], "DENY");
        assert_eq!(
            headers[header::STRICT_TRANSPORT_SECURITY],
            "max-age=31536000; includeSubDomains"
        );
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }

    #[tokio::test]
    async fn hsts_is_sent_only_over_https() {
        let headers = response_headers(false, "/page").await;

        assert!(headers.get(header::STRICT_TRANSPORT_SECURITY).is_none());
        assert!(headers.get(header::CONTENT_SECURITY_POLICY).is_some());
    }

    #[tokio::test]
    async fn static_files_are_revalidated_so_a_deploy_is_seen_at_once() {
        let headers = response_headers(true, "/static/file.css").await;

        assert_eq!(headers[header::CACHE_CONTROL], "no-cache");
        assert_eq!(headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    }

    #[tokio::test]
    async fn redirects_that_set_the_session_cookie_are_never_cached() {
        let headers = response_headers(true, "/callback").await;

        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
    }
}
