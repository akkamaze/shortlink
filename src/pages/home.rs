use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;

use crate::{auth::error::AuthError, auth::session, pages::profile::Profile, state::AppState};

/// Signed-in landing page. Stands in until the links page is built.
#[derive(Template, WebTemplate)]
#[template(path = "pages/home.html")]
pub struct HomePage {
    pub profile: Profile,
}

pub async fn show(State(state): State<AppState>, jar: CookieJar) -> Result<Response, AuthError> {
    let Some(user) = session::current_user(&state.db, &state.keys, &jar).await? else {
        return Ok(Redirect::to("/login").into_response());
    };

    Ok(HomePage {
        profile: Profile::new(user),
    }
    .into_response())
}
