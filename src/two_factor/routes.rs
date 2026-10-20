use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Form,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;

use super::store::{self, Check, Confirm};
use crate::{
    auth::{error::AuthError, signed_in::SignedIn},
    pages::{
        settings::Notice,
        two_factor_setup::{RecoveryCodesPage, SetupPage},
    },
    state::AppState,
};

/// Longer than any app or recovery code; anything longer is refused unread.
const MAX_CODE_LEN: usize = 32;

#[derive(Deserialize)]
pub struct CodeForm {
    code: String,
}

impl CodeForm {
    fn typed(&self) -> &str {
        if self.code.len() > MAX_CODE_LEN {
            ""
        } else {
            &self.code
        }
    }
}

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub async fn start(
    State(state): State<AppState>,
    SignedIn(user): SignedIn,
) -> Result<Redirect, AuthError> {
    store::begin_setup(&state.db, &state.keys, user.id).await?;

    Ok(Redirect::to("/settings/2fa"))
}

/// Turns two-factor on with the first code from the app, then shows the
/// recovery codes once. They are not stored anywhere they could be shown again.
pub async fn confirm(
    State(state): State<AppState>,
    SignedIn(user): SignedIn,
    Form(form): Form<CodeForm>,
) -> Result<Response, AuthError> {
    let outcome = store::confirm(&state.db, &state.keys, user.id, form.typed(), now_unix()).await?;

    let problem = match outcome {
        Confirm::Enabled(codes) => return Ok(RecoveryCodesPage { codes }.into_response()),
        Confirm::NotSettingUp => return Ok(Redirect::to("/settings").into_response()),
        Confirm::WrongCode => Notice::WrongCode,
        Confirm::Locked => Notice::Locked,
    };

    let Some(secret) = store::setup_secret(&state.db, &state.keys, user.id).await? else {
        return Ok(Redirect::to("/settings").into_response());
    };
    let page = SetupPage::new(&secret, Some(problem.message()))?;
    Ok((StatusCode::BAD_REQUEST, page).into_response())
}

/// Turning two-factor off asks for a current code, so a stolen session alone
/// cannot remove it.
pub async fn turn_off(
    State(state): State<AppState>,
    SignedIn(user): SignedIn,
    Form(form): Form<CodeForm>,
) -> Result<Redirect, AuthError> {
    let notice =
        match store::verify(&state.db, &state.keys, user.id, form.typed(), now_unix()).await? {
            Check::Passed => {
                store::turn_off(&state.db, user.id).await?;
                Notice::TurnedOff
            }
            Check::WrongCode => Notice::WrongCode,
            Check::Locked => Notice::Locked,
        };

    Ok(Redirect::to(&format!("/settings?notice={}", notice.code())))
}

/// Drops a setup that was never confirmed. Two-factor that is on stays on.
pub async fn cancel(
    State(state): State<AppState>,
    SignedIn(user): SignedIn,
) -> Result<Redirect, AuthError> {
    if store::status(&state.db, user.id).await? == store::Status::SettingUp {
        store::turn_off(&state.db, user.id).await?;
    }

    Ok(Redirect::to("/settings"))
}
