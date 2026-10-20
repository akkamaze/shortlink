use askama::Template;
use axum::{
    extract::Query,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use axum_extra::extract::PrivateCookieJar;
use serde::Deserialize;

use crate::{
    security_headers::ScriptNonce,
    two_factor::{
        pending::{PENDING_COOKIE, PendingSecondFactor},
        routes::now_unix,
    },
};

/// The second step of signing in, for accounts with two-factor on.
#[derive(Template)]
#[template(path = "pages/two_factor_login.html")]
pub struct SecondFactorPage {
    pub with: CodeKind,
    pub problem: Option<&'static str>,
    pub nonce: ScriptNonce,
}

impl SecondFactorPage {
    pub fn new(with: CodeKind, problem: Option<&'static str>) -> Self {
        Self {
            with,
            problem,
            nonce: ScriptNonce::generate(),
        }
    }
}

/// The page with its own policy, which lets the code-box script run.
impl IntoResponse for SecondFactorPage {
    fn into_response(self) -> Response {
        let policy = self.nonce.policy_header();
        match self.render() {
            Ok(html) => ([policy], Html(html)).into_response(),
            Err(error) => {
                tracing::error!(error = %error, "cannot render the code page");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}

/// Which code the page asks for. The app code is the default; a recovery
/// code has its own form, reached by its own button.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeKind {
    App,
    Recovery,
}

impl CodeKind {
    /// `Some("recovery")` gives the recovery form; anything else the app form.
    pub fn from_param(param: Option<&str>) -> Self {
        match param {
            Some("recovery") => CodeKind::Recovery,
            _ => CodeKind::App,
        }
    }

    pub fn wrong_code_message(self) -> &'static str {
        match self {
            CodeKind::App => "Wrong code. Try the newest one.",
            CodeKind::Recovery => "That recovery code didn't work.",
        }
    }

    pub fn param(self) -> &'static str {
        match self {
            CodeKind::App => "app",
            CodeKind::Recovery => "recovery",
        }
    }
}

#[derive(Deserialize)]
pub struct SecondFactorQuery {
    with: Option<String>,
}

pub async fn show(private: PrivateCookieJar, Query(query): Query<SecondFactorQuery>) -> Response {
    if waiting(&private).is_none() {
        return Redirect::to("/login?problem=expired").into_response();
    }

    SecondFactorPage::new(CodeKind::from_param(query.with.as_deref()), None).into_response()
}

pub fn waiting(private: &PrivateCookieJar) -> Option<PendingSecondFactor> {
    private
        .get(PENDING_COOKIE)
        .and_then(|cookie| PendingSecondFactor::decode(cookie.value(), now_unix()))
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::{CodeKind, SecondFactorPage};

    fn page(with: CodeKind, problem: Option<&'static str>) -> String {
        SecondFactorPage::new(with, problem).render().unwrap()
    }

    #[test]
    fn the_app_form_takes_six_digits_and_offers_the_recovery_form() {
        let html = page(CodeKind::App, None);

        assert!(html.contains(r#"maxlength="6""#));
        assert!(html.contains(r#"class="code-field__cells" aria-hidden="true""#));
        assert!(html.contains(r#"data-code-field="numeric""#));
        assert_eq!(html.matches("data-slot").count(), 6);
        assert!(html.contains(r#"inputmode="numeric""#));
        assert!(html.contains(r#"autocomplete="one-time-code""#));
        assert!(html.contains(r#"href="/login/2fa?with=recovery""#));
        assert!(html.contains("Trust this device"));
        assert!(!html.contains(r#"role="alert""#));
    }

    #[test]
    fn the_recovery_form_takes_letters_and_offers_the_app_form_back() {
        let html = page(CodeKind::Recovery, None);

        assert!(html.contains(r#"name="with" value="recovery""#));
        assert!(html.contains(r#"data-code-groups="5,5""#));
        assert!(!html.contains(r#"inputmode="numeric""#));
        assert!(html.contains(r#"href="/login/2fa""#));
        assert!(
            !html.contains(r#"name="trust""#),
            "a recovery code never trusts the browser"
        );
    }

    #[test]
    fn only_recovery_selects_the_recovery_form() {
        assert_eq!(CodeKind::from_param(Some("recovery")), CodeKind::Recovery);
        for other in [None, Some("app"), Some("<b>")] {
            assert_eq!(CodeKind::from_param(other), CodeKind::App, "{other:?}");
        }
    }

    #[test]
    fn the_box_script_carries_this_pages_nonce() {
        let page = SecondFactorPage::new(CodeKind::App, None);
        let nonce = page.nonce.as_str().to_owned();
        let html = page.render().unwrap();

        assert!(html.contains(&format!(r#"nonce="{nonce}""#)));
        assert!(html.contains("/static/js/code-field.js"));
    }

    #[test]
    fn a_problem_is_an_alert() {
        assert!(page(CodeKind::App, Some("Wrong code.")).contains(r#"role="alert""#));
    }
}
