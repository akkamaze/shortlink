/// The login hero's demo: one long link and how short it gets with a
/// random slug.
pub struct LengthDemo {
    pub long_url: &'static str,
    pub long_len: usize,
    pub host: &'static str,
    pub random_slug: &'static str,
    pub random_len: usize,
    pub random_saving: usize,
}

const HOST: &str = "synq.li/";

pub fn login_demo() -> LengthDemo {
    let long_url = "https://link.synqloud.com/?utm_source=synq.li&utm_medium=short-link&utm_campaign=login-demo";
    let random_slug = "R3vt8w";

    let long_len = char_len(long_url);
    let random_len = char_len(HOST) + char_len(random_slug);

    LengthDemo {
        long_url,
        long_len,
        host: HOST,
        random_slug,
        random_len,
        random_saving: percent_shorter(long_len, random_len),
    }
}

fn char_len(text: &str) -> usize {
    text.chars().count()
}

/// `91` characters down to `14` is `85` percent shorter.
fn percent_shorter(long: usize, short: usize) -> usize {
    (100 * (long - short) + long / 2) / long
}

#[cfg(test)]
mod tests {
    use super::{char_len, login_demo, percent_shorter};

    #[test]
    fn lengths_count_characters_not_bytes() {
        assert_eq!(char_len("ตัวอย่าง.th"), 11);
    }

    #[test]
    fn the_demo_shrinks_91_characters_to_14() {
        let demo = login_demo();

        assert_eq!((demo.long_len, demo.random_len), (91, 14));
        assert_eq!(demo.random_saving, 85);
    }

    #[test]
    fn savings_round_to_the_nearest_percent() {
        assert_eq!(percent_shorter(91, 17), 81);
        assert_eq!(percent_shorter(200, 1), 100);
        assert_eq!(percent_shorter(3, 2), 33);
    }
}
