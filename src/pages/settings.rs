use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::{
    auth::{error::AuthError, signed_in::SignedIn},
    pages::profile::Profile,
    state::AppState,
    two_factor::store::{self, Status},
};

#[derive(Template, WebTemplate)]
#[template(path = "pages/settings.html")]
pub struct SettingsPage {
    pub profile: Profile,
    pub two_factor: Status,
    pub notice: Option<Notice>,
}

/// A line shown above the two-factor section after an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Notice {
    TurnedOff,
    DevicesForgotten,
    WrongCode,
    Locked,
}

impl Notice {
    const ALL: [Notice; 4] = [
        Notice::TurnedOff,
        Notice::DevicesForgotten,
        Notice::WrongCode,
        Notice::Locked,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Notice::TurnedOff => "two-factor-off",
            Notice::DevicesForgotten => "devices-forgotten",
            Notice::WrongCode => "wrong-code",
            Notice::Locked => "locked",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|notice| notice.code() == code)
    }

    pub fn message(self) -> &'static str {
        match self {
            Notice::TurnedOff => "Two-factor sign-in is off.",
            Notice::DevicesForgotten => "Every browser will ask for a code at its next sign-in.",
            Notice::WrongCode => "That code did not work. Try the newest one from your app.",
            Notice::Locked => "Too many tries. Wait 15 minutes.",
        }
    }

    pub fn is_problem(self) -> bool {
        matches!(self, Notice::WrongCode | Notice::Locked)
    }
}

#[derive(Deserialize)]
pub struct SettingsQuery {
    notice: Option<String>,
}

pub async fn show(
    State(state): State<AppState>,
    SignedIn(user): SignedIn,
    Query(query): Query<SettingsQuery>,
) -> Result<Response, AuthError> {
    let two_factor = store::status(&state.db, user.id).await?;
    let notice = query.notice.as_deref().and_then(Notice::from_code);
    let status = match notice {
        Some(notice) if notice.is_problem() => StatusCode::BAD_REQUEST,
        _ => StatusCode::OK,
    };

    let page = SettingsPage {
        profile: Profile::new(user),
        two_factor,
        notice,
    };
    Ok((status, page).into_response())
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::{Notice, SettingsPage};
    use crate::{pages::profile::Profile, two_factor::store::Status};

    fn page(two_factor: Status, notice: Option<Notice>) -> String {
        SettingsPage {
            profile: Profile {
                name: "Ann".to_owned(),
                email: None,
                picture: None,
                initial: "A".to_owned(),
            },
            two_factor,
            notice,
        }
        .render()
        .unwrap()
    }

    #[test]
    fn each_status_offers_its_own_next_step() {
        assert!(page(Status::Off, None).contains(r#"action="/settings/2fa/start""#));
        assert!(page(Status::SettingUp, None).contains(r#"href="/settings/2fa""#));

        let on = page(Status::On, None);
        assert!(on.contains(r#"action="/settings/2fa/off""#));
        assert!(on.contains(r#"name="code""#), "turning off asks for a code");
        assert!(on.contains(r#"action="/settings/2fa/forget-devices""#));
        assert!(on.contains(r#"action="/settings/2fa/recovery-codes""#));
    }

    #[test]
    fn notices_round_trip_and_problems_are_alerts() {
        for notice in Notice::ALL {
            assert_eq!(Notice::from_code(notice.code()), Some(notice));
        }
        assert_eq!(Notice::from_code("<b>"), None);

        assert!(page(Status::On, Some(Notice::WrongCode)).contains(r#"role="alert""#));
        assert!(page(Status::Off, Some(Notice::TurnedOff)).contains(r#"role="status""#));
    }
}
