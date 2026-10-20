use askama::Template;
use askama_web::WebTemplate;
use axum::{
    extract::State,
    response::{IntoResponse, Redirect, Response},
};
use qrcode::{QrCode, render::svg};

use crate::{
    auth::{error::AuthError, signed_in::SignedIn},
    state::AppState,
    two_factor::{store, totp},
};

/// Shows the QR code and key for a setup in progress.
#[derive(Template, WebTemplate)]
#[template(path = "pages/two_factor_setup.html")]
pub struct SetupPage {
    pub qr_svg: String,
    pub key_groups: Vec<String>,
    pub problem: Option<&'static str>,
}

/// Shown once, right after two-factor turns on.
#[derive(Template, WebTemplate)]
#[template(path = "pages/recovery_codes.html")]
pub struct RecoveryCodesPage {
    pub codes: Vec<String>,
}

impl RecoveryCodesPage {
    /// A `data:` link the browser saves as a text file, so the codes never
    /// travel back to the server to be downloaded.
    pub fn download_href(&self) -> String {
        let text = format!(
            "shortlink recovery codes\nEach code lets you log in once.\n\n{}\n",
            self.codes.join("\n")
        );
        format!("data:text/plain;charset=utf-8,{}", percent_encode(&text))
    }
}

/// `"A-1\n"` gives `"A-1%0A"`: letters, digits and `-` stay, the rest is escaped.
fn percent_encode(text: &str) -> String {
    text.bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' => char::from(byte).to_string(),
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

impl SetupPage {
    pub fn new(secret_base32: &str, problem: Option<&'static str>) -> anyhow::Result<Self> {
        Ok(Self {
            qr_svg: qr_svg(&totp::provisioning_uri(secret_base32))?,
            key_groups: key_groups(secret_base32),
            problem,
        })
    }
}

pub async fn show(
    State(state): State<AppState>,
    SignedIn(user): SignedIn,
) -> Result<Response, AuthError> {
    let Some(secret) = store::setup_secret(&state.db, &state.keys, user.id).await? else {
        return Ok(Redirect::to("/settings").into_response());
    };

    Ok(SetupPage::new(&secret, None)?.into_response())
}

/// Dark modules on white with a quiet zone, which every scanner reads.
fn qr_svg(data: &str) -> anyhow::Result<String> {
    let code = QrCode::new(data.as_bytes())?;

    Ok(code
        .render::<svg::Color>()
        .min_dimensions(192, 192)
        .dark_color(svg::Color("#080e17"))
        .light_color(svg::Color("#ffffff"))
        .build())
}

/// `"ABCDEFGHIJ"` gives `["ABCD", "EFGH", "IJ"]`, easier to type by hand.
fn key_groups(secret_base32: &str) -> Vec<String> {
    secret_base32
        .as_bytes()
        .chunks(4)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::{RecoveryCodesPage, SetupPage, key_groups};

    #[test]
    fn the_key_is_split_into_groups_of_four() {
        assert_eq!(key_groups("ABCDEFGHIJ"), ["ABCD", "EFGH", "IJ"]);
    }

    #[test]
    fn the_setup_page_draws_a_qr_and_confirms_with_a_post() {
        let html = SetupPage::new("JBSWY3DPEHPK3PXP", None)
            .unwrap()
            .render()
            .unwrap();

        assert!(html.contains("<svg"));
        assert!(html.contains("JBSW"));
        assert!(html.contains(r#"action="/settings/2fa/confirm""#));
        assert!(!html.contains("<script"));
    }

    #[test]
    fn recovery_codes_are_listed_once_with_a_way_back() {
        let html = RecoveryCodesPage {
            codes: vec!["AAAAA-BBBBB".to_owned(), "CCCCC-DDDDD".to_owned()],
        }
        .render()
        .unwrap();

        assert!(html.contains("AAAAA-BBBBB") && html.contains("CCCCC-DDDDD"));
        assert!(html.contains(r#"href="/settings""#));
        assert!(html.contains(r#"download="shortlink-recovery-codes.txt""#));
        assert!(html.contains("data:text/plain;charset=utf-8,shortlink%20recovery%20codes"));
        assert!(html.contains("AAAAA-BBBBB%0ACCCCC-DDDDD%0A"));
    }
}
