use crate::auth::session::CurrentUser;

/// The signed-in person as pages show them.
pub struct Profile {
    pub name: String,
    pub email: Option<String>,
    pub picture: Option<String>,
    pub initial: String,
}

impl Profile {
    /// `Ann Lee` gives the initial `A`; with no name, the email stands in.
    pub fn new(user: CurrentUser) -> Self {
        let name = user
            .display_name
            .or_else(|| user.email.clone())
            .unwrap_or_else(|| "there".to_owned());
        let initial = name
            .chars()
            .next()
            .map(char::to_uppercase)
            .map_or_else(String::new, String::from_iter);

        Self {
            name,
            email: user.email,
            picture: user.picture.map(|picture| picture.as_str().to_owned()),
            initial,
        }
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::Profile;
    use crate::auth::session::CurrentUser;

    fn user(display_name: Option<&str>, email: Option<&str>) -> CurrentUser {
        CurrentUser {
            id: Uuid::nil(),
            email: email.map(str::to_owned),
            display_name: display_name.map(str::to_owned),
            picture: None,
        }
    }

    #[test]
    fn the_name_falls_back_to_the_email_then_a_greeting() {
        let named = Profile::new(user(Some("ann lee"), Some("ann@example.com")));
        let email_only = Profile::new(user(None, Some("bo@example.com")));
        let line_without_name = Profile::new(user(None, None));

        assert_eq!(
            (named.name.as_str(), named.initial.as_str()),
            ("ann lee", "A")
        );
        assert_eq!(email_only.name, "bo@example.com");
        assert_eq!(line_without_name.name, "there");
    }
}
