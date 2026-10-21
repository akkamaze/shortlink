use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{CookieJar, PrivateCookieJar};
use serde::Deserialize;

use super::{
    accounts,
    error::AuthError,
    pending_login::{LOGIN_COOKIE, PendingLogin},
    provider::Provider,
    provider_error, session,
};
use crate::{
    state::AppState,
    two_factor::{
        pending::PendingSecondFactor,
        routes::now_unix,
        store::{self, Status},
        trusted,
    },
};

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

pub async fn start(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    private: PrivateCookieJar,
) -> Result<(PrivateCookieJar, Redirect), StatusCode> {
    let provider = Provider::from_slug(&slug).ok_or(StatusCode::NOT_FOUND)?;
    let (url, pending) = state
        .providers
        .begin(provider)
        .ok_or(StatusCode::NOT_FOUND)?;

    let private = private.add(pending.into_cookie(state.secure_cookies));
    Ok((private, Redirect::to(url.as_str())))
}

pub async fn callback(
    State(state): State<AppState>,
    Path(slug): Path<String>,
    Query(params): Query<CallbackParams>,
    private: PrivateCookieJar,
    jar: CookieJar,
) -> Response {
    let pending = private
        .get(LOGIN_COOKIE)
        .and_then(|cookie| PendingLogin::decode(cookie.value()));
    let private = private.remove(PendingLogin::removal_cookie());

    match complete_sign_in(&state, &slug, params, pending, &jar).await {
        Ok(SignedIn::Done(token)) => {
            let jar = jar.add(token.into_cookie(state.secure_cookies));
            (private, jar, Redirect::to("/app")).into_response()
        }
        Ok(SignedIn::NeedsCode(waiting)) => {
            let private = private.add(waiting.into_cookie(state.secure_cookies));
            (private, Redirect::to("/login/2fa")).into_response()
        }
        Err(error) => (private, error).into_response(),
    }
}

/// An account with two-factor on gets its session only after the code,
/// unless this browser was trusted.
enum SignedIn {
    Done(session::SessionToken),
    NeedsCode(PendingSecondFactor),
}

async fn complete_sign_in(
    state: &AppState,
    slug: &str,
    params: CallbackParams,
    pending: Option<PendingLogin>,
    jar: &CookieJar,
) -> Result<SignedIn, AuthError> {
    if let Some(reason) = params.error {
        return Err(AuthError::Cancelled(
            provider_error::callback_error_code(&reason).to_owned(),
        ));
    }

    let pending = pending
        .filter(|pending| pending.provider.slug() == slug)
        .filter(|pending| params.state.as_deref() == Some(pending.state.as_str()))
        .ok_or(AuthError::Expired)?;
    let code = params.code.ok_or(AuthError::Expired)?;

    let identity = state.providers.finish(pending, code).await?;
    let user_id = accounts::sign_in(&state.db, &state.keys, &identity).await?;

    let asks_for_code = store::status(&state.db, user_id).await? == Status::On
        && !trusted::is_trusted(&state.db, jar, user_id).await?;
    if asks_for_code {
        return Ok(SignedIn::NeedsCode(PendingSecondFactor::new(
            user_id,
            now_unix(),
        )));
    }
    Ok(SignedIn::Done(session::create(&state.db, user_id).await?))
}

pub async fn logout(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), AuthError> {
    session::delete(&state.db, &jar).await?;

    Ok((
        jar.remove(session::removal_cookie()),
        Redirect::to("/login"),
    ))
}
