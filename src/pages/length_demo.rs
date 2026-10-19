/// The login hero's demo: one long link and how short it gets.
pub struct LengthDemo {
    pub long_url: &'static str,
    pub long_len: usize,
}

pub fn login_demo() -> LengthDemo {
    let long_url = "https://link.synqloud.com/?utm_source=synq.li&utm_medium=short-link&utm_campaign=login-demo";

    LengthDemo {
        long_url,
        long_len: char_len(long_url),
    }
}

fn char_len(text: &str) -> usize {
    text.chars().count()
}

#[cfg(test)]
mod tests {
    use super::{char_len, login_demo};

    #[test]
    fn lengths_count_characters_not_bytes() {
        assert_eq!(char_len("ตัวอย่าง.th"), 11);
        assert_eq!(login_demo().long_len, 91);
    }
}
