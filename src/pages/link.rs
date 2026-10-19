use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use axum_extra::extract::{CookieJar, PrivateCookieJar};

use crate::{
    auth::{
        accounts,
        error::AuthError,
        pending_link::{LINK_COOKIE, PendingLink},
        provider::Provider,
        session,
    },
    pages::login::{ButtonState, LoginButton},
    state::AppState,
};

/// Asks before a sign-in joins an account that already has its email.
#[derive(Template, WebTemplate)]
#[template(path = "pages/link.html")]
pub struct LinkPage {
    pub adding: &'static str,
    pub step: LinkStep,
}

pub enum LinkStep {
    /// The account's owner is signed in and can add the new sign-in.
    Confirm,
    /// Someone must first prove they own the account, with one of its sign-ins.
    SignInFirst { buttons: Vec<LoginButton> },
}

pub async fn show(
    State(state): State<AppState>,
    private: PrivateCookieJar,
    jar: CookieJar,
) -> Result<Response, AuthError> {
    let Some(link) = private
        .get(LINK_COOKIE)
        .and_then(|cookie| PendingLink::decode(cookie.value()))
    else {
        return Ok(Redirect::to("/login").into_response());
    };

    let signed_in = session::current_user(&state.db, &state.keys, &jar).await?;
    let step = if signed_in.is_some_and(|user| user.id == link.holder) {
        LinkStep::Confirm
    } else {
        let enabled = state.providers.enabled();
        let providers = accounts::sign_in_providers(&state.db, link.holder).await?;
        LinkStep::SignInFirst {
            buttons: holder_buttons(&providers, &enabled, link.identity.provider),
        }
    };

    Ok(LinkPage {
        adding: link.identity.provider.label(),
        step,
    }
    .into_response())
}

/// `[Google, LINE]` held, LINE switched off, adding Facebook: one Google button.
fn holder_buttons(held: &[Provider], enabled: &[Provider], adding: Provider) -> Vec<LoginButton> {
    held.iter()
        .filter(|provider| **provider != adding && enabled.contains(provider))
        .map(|provider| LoginButton {
            slug: provider.slug(),
            label: provider.label(),
            state: ButtonState::Ready,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::{LinkPage, LinkStep, holder_buttons};
    use crate::auth::provider::Provider;

    #[test]
    fn offers_the_holders_enabled_sign_ins_but_not_the_one_being_added() {
        let buttons = holder_buttons(
            &[Provider::Google, Provider::Line],
            &[Provider::Google],
            Provider::Line,
        );

        let slugs: Vec<&str> = buttons.iter().map(|button| button.slug).collect();
        assert_eq!(slugs, ["google"]);
    }

    #[test]
    fn the_owner_confirms_with_a_post_form() {
        let html = LinkPage {
            adding: "LINE",
            step: LinkStep::Confirm,
        }
        .render()
        .unwrap();

        assert!(html.contains(r#"action="/link/confirm""#));
        assert!(html.contains("Add LINE"));
        assert!(!html.contains(r#"href="/auth/"#));
    }

    #[test]
    fn others_must_sign_in_first_or_start_a_separate_account() {
        let html = LinkPage {
            adding: "LINE",
            step: LinkStep::SignInFirst {
                buttons: holder_buttons(&[Provider::Google], &[Provider::Google], Provider::Line),
            },
        }
        .render()
        .unwrap();

        assert!(html.contains(r#"href="/auth/google/start""#));
        assert!(html.contains(r#"action="/link/separate""#));
        assert!(!html.contains(r#"action="/link/confirm""#));
    }
}
