use askama::Template;
use askama_web::WebTemplate;

#[derive(Template, WebTemplate)]
#[template(path = "pages/login.html")]
pub struct LoginPage {}

pub async fn show() -> LoginPage {
    LoginPage {}
}
