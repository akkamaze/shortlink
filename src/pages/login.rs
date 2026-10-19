use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

use crate::{
    auth::{error::Problem, provider::Provider, session},
    pages::length_demo::{LengthDemo, login_demo},
    state::AppState,
};

#[derive(Template, WebTemplate)]
#[template(path = "pages/login.html")]
pub struct LoginPage {
    pub buttons: Vec<LoginButton>,
    pub demo: LengthDemo,
    pub problem: Option<&'static str>,
}

pub struct LoginButton {
    pub slug: &'static str,
    pub label: &'static str,
    pub state: ButtonState,
}

pub enum ButtonState {
    Ready,
    Soon,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    problem: Option<String>,
}

/// Every way to log in the design shows, in its order. A button works once
/// its provider is configured; the rest show as Soon.
const DESIGN_ORDER: [(&str, &str); 4] = [
    ("google", "Google"),
    ("facebook", "Facebook"),
    ("line", "LINE"),
    ("email", "email"),
];

impl LoginPage {
    pub fn new(problem: Option<Problem>, enabled: &[Provider]) -> Self {
        Self {
            buttons: login_buttons(enabled),
            demo: login_demo(),
            problem: problem.map(Problem::message),
        }
    }
}

fn login_buttons(enabled: &[Provider]) -> Vec<LoginButton> {
    DESIGN_ORDER
        .into_iter()
        .map(|(slug, label)| LoginButton {
            slug,
            label,
            state: match Provider::from_slug(slug) {
                Some(provider) if enabled.contains(&provider) => ButtonState::Ready,
                _ => ButtonState::Soon,
            },
        })
        .collect()
}

/// Never redirects on a failed session lookup, so a database outage cannot
/// bounce the browser between `/login` and itself.
pub async fn show(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
    jar: CookieJar,
) -> Response {
    let mut problem = query.problem.as_deref().and_then(Problem::from_code);

    match session::current_user(&state.db, &state.keys, &jar).await {
        Ok(Some(_)) => return Redirect::to("/app").into_response(),
        Ok(None) => {}
        Err(error) => {
            tracing::error!(error = %error, "cannot check the session on the login page");
            problem = Some(Problem::ServerError);
        }
    }

    let status = problem.map_or(StatusCode::OK, Problem::status);
    let page = LoginPage::new(problem, &state.oidc.enabled());

    (status, page).into_response()
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::LoginPage;
    use crate::auth::{error::Problem, provider::Provider};

    #[test]
    fn google_signs_in_and_the_other_buttons_wait() {
        let html = LoginPage::new(None, &[Provider::Google]).render().unwrap();

        let labels: Vec<&str> = html
            .match_indices("Continue with ")
            .map(|(at, _)| html[at..].split('<').next().unwrap())
            .collect();

        assert_eq!(
            labels,
            [
                "Continue with Google",
                "Continue with Facebook",
                "Continue with LINE",
                "Continue with email"
            ]
        );
        assert_eq!(html.matches(r#"href="/auth/"#).count(), 1);
        assert!(html.contains(r#"href="/auth/google/start""#));
        assert_eq!(html.matches(r#"aria-disabled="true""#).count(), 3);
    }

    #[test]
    fn line_signs_in_once_it_is_configured() {
        let html = LoginPage::new(None, &[Provider::Google, Provider::Line])
            .render()
            .unwrap();

        assert!(html.contains(r#"href="/auth/line/start""#));
        assert_eq!(html.matches(r#"aria-disabled="true""#).count(), 2);
    }

    #[test]
    fn a_sign_in_problem_is_shown_as_an_alert() {
        let html = LoginPage::new(Some(Problem::Expired), &[Provider::Google])
            .render()
            .unwrap();

        assert!(html.contains(r#"role="alert""#));
        assert!(html.contains(Problem::Expired.message()));
        assert!(
            !LoginPage::new(None, &[Provider::Google])
                .render()
                .unwrap()
                .contains(r#"role="alert""#)
        );
    }

    #[test]
    fn stylesheets_carry_the_asset_version() {
        let html = LoginPage::new(None, &[Provider::Google]).render().unwrap();

        let stylesheets: Vec<&str> = html
            .split(r#"rel="stylesheet" href=""#)
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap())
            .collect();

        assert!(!stylesheets.is_empty());
        for href in stylesheets {
            assert!(
                href.ends_with(&format!("?v={}", crate::assets::VERSION)),
                "{href}"
            );
        }
    }
}
