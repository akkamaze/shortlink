use axum::http::Request;
use tracing::Span;

/// The span for one request. Query strings are left out because they can
/// carry secrets, such as an OAuth callback's code and state.
pub fn request_span<B>(request: &Request<B>) -> Span {
    tracing::info_span!(
        "request",
        method = %request.method(),
        path = %request.uri().path(),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use axum::http::Request;
    use tracing_subscriber::fmt::MakeWriter;

    use super::request_span;

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Captured {
        type Writer = Captured;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn callback_code_and_state_never_reach_the_log() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_writer(captured.clone())
            .finish();
        let request = Request::get("/auth/google/callback?code=SECRET-CODE&state=SECRET-STATE")
            .body(())
            .unwrap();

        tracing::subscriber::with_default(subscriber, || {
            let _entered = request_span(&request).entered();
            tracing::debug!("handled");
        });

        let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert!(
            log.contains("/auth/google/callback"),
            "path is logged: {log}"
        );
        assert!(!log.contains("SECRET"), "query is not logged: {log}");
    }
}
