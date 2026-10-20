use axum::{
    extract::FromRequestParts,
    http::request::Parts,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::CookieJar;

use super::{
    error::AuthError,
    session::{self, CurrentUser},
};
use crate::state::AppState;

/// The person behind the session cookie. A handler that takes it is only
/// reached when someone is signed in; everyone else goes to `/login`.
pub struct SignedIn(pub CurrentUser);

impl FromRequestParts<AppState> for SignedIn {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let jar = CookieJar::from_headers(&parts.headers);

        match session::current_user(&state.db, &state.keys, &jar).await {
            Ok(Some(user)) => Ok(SignedIn(user)),
            Ok(None) => Err(Redirect::to("/login").into_response()),
            Err(error) => Err(AuthError::Internal(error).into_response()),
        }
    }
}
