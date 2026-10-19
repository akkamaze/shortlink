use axum::{
    Router,
    extract::Path,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};

use super::reserved::reserved;

/// Static app routes such as `/login` win over `/{slug}`: the router ranks
/// static segments above captures.
pub fn router<S: Clone + Send + Sync + 'static>() -> Router<S> {
    Router::new().route("/{slug}", get(follow))
}

/// Follows a short link. Only reserved slugs exist so far; 302 lets a
/// destination change later without browsers holding on to the old one.
pub async fn follow(Path(slug): Path<String>) -> Response {
    match reserved(&slug) {
        Some(destination) => (StatusCode::FOUND, [(header::LOCATION, destination)]).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode, header},
    };
    use tower::ServiceExt;

    use super::router;
    use crate::links::reserved::SHORTLINK_HOME;

    async fn get(path: &str) -> (StatusCode, Option<String>) {
        let response = router::<()>()
            .oneshot(Request::get(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str().unwrap().to_owned());

        (response.status(), location)
    }

    #[tokio::test]
    async fn reserved_slugs_redirect_in_any_case() {
        for path in ["/shortlink", "/ShortLink"] {
            assert_eq!(
                get(path).await,
                (StatusCode::FOUND, Some(SHORTLINK_HOME.to_owned())),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn unknown_slugs_are_not_found() {
        assert_eq!(get("/no-such-link").await, (StatusCode::NOT_FOUND, None));
    }
}
