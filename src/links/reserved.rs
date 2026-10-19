pub const SHORTLINK_HOME: &str = "https://link.synqloud.com/";

const SYNQLOUD_HOME: &str = "https://synqloud.com/";

/// Slugs nobody can create, each with its fixed destination. Kept in code
/// rather than the database, so a changed row cannot repoint a brand slug
/// and every change goes through review.
const RESERVED: [(&str, &str); 3] = [
    ("shortlink", SHORTLINK_HOME),
    ("synqloud", SYNQLOUD_HOME),
    ("r3vt8w", SHORTLINK_HOME),
];

/// Where a reserved slug leads. Case is ignored, so `ShortLink` is as taken
/// as `shortlink`: a reader sees the same name either way.
pub fn reserved(slug: &str) -> Option<&'static str> {
    RESERVED
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(slug))
        .map(|(_, destination)| *destination)
}

#[cfg(test)]
mod tests {
    use super::{RESERVED, SHORTLINK_HOME, reserved};

    #[test]
    fn brand_and_demo_slugs_are_taken_in_any_case() {
        for slug in ["shortlink", "ShortLink", "SYNQLOUD", "R3vt8w"] {
            assert!(reserved(slug).is_some(), "{slug}");
        }

        assert_eq!(reserved("shortlink"), Some(SHORTLINK_HOME));
        assert_eq!(reserved("synqloud"), Some("https://synqloud.com/"));
    }

    #[test]
    fn other_slugs_stay_free() {
        for slug in ["team", "shortlinks", "login", "admin", "k7Qx2m", ""] {
            assert_eq!(reserved(slug), None, "{slug}");
        }
    }

    #[test]
    fn every_entry_is_lowercase_and_listed_once() {
        for (index, (name, _)) in RESERVED.iter().enumerate() {
            assert_eq!(*name, name.to_lowercase(), "{name}");
            assert!(
                RESERVED[..index].iter().all(|(earlier, _)| earlier != name),
                "{name} is listed twice"
            );
        }
    }
}
