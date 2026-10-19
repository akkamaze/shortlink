use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{CookieJar, PrivateCookieJar};

use super::{
    accounts::{self, Attach},
    error::AuthError,
    pending_link::{LINK_COOKIE, PendingLink},
    session,
};
use crate::state::AppState;

/// Adds the waiting sign-in to the account, but only for that account's
/// signed-in owner. A POST, so the CSRF layer stops other sites from sending it.
pub async fn confirm(
    State(state): State<AppState>,
    private: PrivateCookieJar,
    jar: CookieJar,
) -> Result<Response, AuthError> {
    let Some(link) = waiting(&private) else {
        return Ok(Redirect::to("/app").into_response());
    };
    let private = private.remove(PendingLink::removal_cookie());

    let owner = session::current_user(&state.db, &state.keys, &jar).await?;
    if owner.is_none_or(|user| user.id != link.holder) {
        return Ok((private, Redirect::to("/login")).into_response());
    }

    match accounts::attach(&state.db, &state.keys, link.holder, &link.identity).await? {
        Attach::Attached => {
            tracing::info!(provider = link.identity.provider.slug(), "sign-in added");
        }
        Attach::OwnedElsewhere => {
            tracing::warn!("sign-in to add already opens another account; left as it is");
        }
    }

    Ok((private, Redirect::to("/app")).into_response())
}

/// Gives the waiting sign-in an account of its own and signs it in.
pub async fn separate(
    State(state): State<AppState>,
    private: PrivateCookieJar,
    jar: CookieJar,
) -> Result<Response, AuthError> {
    let Some(link) = waiting(&private) else {
        return Ok(Redirect::to("/login").into_response());
    };
    let private = private.remove(PendingLink::removal_cookie());

    let user_id = accounts::create_separate(&state.db, &state.keys, &link.identity).await?;
    let token = session::create(&state.db, user_id).await?;
    let jar = jar.add(token.into_cookie(state.secure_cookies));

    Ok((private, jar, Redirect::to("/app")).into_response())
}

pub async fn cancel(private: PrivateCookieJar) -> (PrivateCookieJar, Redirect) {
    (
        private.remove(PendingLink::removal_cookie()),
        Redirect::to("/login"),
    )
}

fn waiting(private: &PrivateCookieJar) -> Option<PendingLink> {
    private
        .get(LINK_COOKIE)
        .and_then(|cookie| PendingLink::decode(cookie.value()))
}
