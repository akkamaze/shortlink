use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;

use crate::{auth::error::AuthError, auth::session, state::AppState};

/// Signed-in landing page. Stands in until the links page is built.
#[derive(Template, WebTemplate)]
#[template(path = "pages/home.html")]
pub struct HomePage {
    pub display_name: String,
    pub email: Option<String>,
}

pub async fn show(State(state): State<AppState>, jar: CookieJar) -> Result<Response, AuthError> {
    let Some(user) = session::current_user(&state.db, &state.keys, &jar).await? else {
        return Ok(Redirect::to("/login").into_response());
    };

    let display_name = user
        .display_name
        .or_else(|| user.email.clone())
        .unwrap_or_else(|| "there".to_owned());
    Ok(HomePage {
        display_name,
        email: user.email,
    }
    .into_response())
}
