use askama::Template;
use askama_web::WebTemplate;

#[derive(Template, WebTemplate)]
#[template(path = "pages/login.html")]
pub struct LoginPage {
    pub buttons: Vec<LoginButton>,
}

pub struct LoginButton {
    pub slug: &'static str,
    pub label: &'static str,
}

/// Every way to log in the design shows, in its order. None has a provider
/// behind it yet, so each is shown but cannot be pressed.
const DESIGN_ORDER: [(&str, &str); 2] = [("google", "Google"), ("facebook", "Facebook")];

pub async fn show() -> LoginPage {
    LoginPage {
        buttons: DESIGN_ORDER
            .into_iter()
            .map(|(slug, label)| LoginButton { slug, label })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use askama::Template;

    use super::show;

    #[tokio::test]
    async fn every_design_button_shows_in_order_and_none_can_be_pressed() {
        let html = show().await.render().unwrap();

        let labels: Vec<&str> = html
            .match_indices("Continue with ")
            .map(|(at, _)| html[at..].split('<').next().unwrap())
            .collect();

        assert_eq!(labels, ["Continue with Google", "Continue with Facebook"]);
        assert!(!html.contains("/auth/"), "no button links to a sign-in yet");
        assert_eq!(html.matches(r#"aria-disabled="true""#).count(), 2);
    }
}
