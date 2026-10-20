use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::Query,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::PrivateCookieJar;
use serde::Deserialize;

use crate::two_factor::{
    pending::{PENDING_COOKIE, PendingSecondFactor},
    routes::now_unix,
};

/// The second step of signing in, for accounts with two-factor on.
#[derive(Template, WebTemplate)]
#[template(path = "pages/two_factor_login.html")]
pub struct SecondFactorPage {
    pub with: CodeKind,
    pub problem: Option<&'static str>,
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
            CodeKind::App => "That code did not work. Try the newest one from your app.",
            CodeKind::Recovery => "That recovery code did not work. Check it, or try another one.",
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

    SecondFactorPage {
        with: CodeKind::from_param(query.with.as_deref()),
        problem: None,
    }
    .into_response()
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
        SecondFactorPage { with, problem }.render().unwrap()
    }

    #[test]
    fn the_app_form_takes_six_digits_and_offers_the_recovery_form() {
        let html = page(CodeKind::App, None);

        assert!(html.contains(r#"maxlength="6""#));
        assert!(html.contains(r#"class="code-field__cells" aria-hidden="true""#));
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
    fn a_problem_is_an_alert() {
        assert!(page(CodeKind::App, Some("That code did not work.")).contains(r#"role="alert""#));
    }
}
