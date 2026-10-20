use askama::Template;
use askama_web::WebTemplate;
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::PrivateCookieJar;

use crate::two_factor::{
    pending::{PENDING_COOKIE, PendingSecondFactor},
    routes::now_unix,
};

/// The second step of signing in, for accounts with two-factor on.
#[derive(Template, WebTemplate)]
#[template(path = "pages/two_factor_login.html")]
pub struct SecondFactorPage {
    pub problem: Option<&'static str>,
}

pub async fn show(private: PrivateCookieJar) -> Response {
    if waiting(&private).is_none() {
        return Redirect::to("/login?problem=expired").into_response();
    }

    SecondFactorPage { problem: None }.into_response()
}

pub fn waiting(private: &PrivateCookieJar) -> Option<PendingSecondFactor> {
    private
        .get(PENDING_COOKIE)
        .and_then(|cookie| PendingSecondFactor::decode(cookie.value(), now_unix()))
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::SecondFactorPage;

    #[test]
    fn asks_for_an_app_or_recovery_code_with_a_post() {
        let html = SecondFactorPage { problem: None }.render().unwrap();

        assert!(html.contains(r#"action="/login/2fa""#));
        assert!(html.contains(r#"autocomplete="one-time-code""#));
        assert!(!html.contains(r#"role="alert""#));
    }

    #[test]
    fn a_problem_is_an_alert() {
        let html = SecondFactorPage {
            problem: Some("That code did not work."),
        }
        .render()
        .unwrap();

        assert!(html.contains(r#"role="alert""#));
    }
}
