use askama::Template;
use askama_web::WebTemplate;

use crate::{auth::signed_in::SignedIn, pages::profile::Profile};

/// Signed-in landing page. Stands in until the links page is built.
#[derive(Template, WebTemplate)]
#[template(path = "pages/home.html")]
pub struct HomePage {
    pub profile: Profile,
}

pub async fn show(SignedIn(user): SignedIn) -> HomePage {
    HomePage {
        profile: Profile::new(user),
    }
}
