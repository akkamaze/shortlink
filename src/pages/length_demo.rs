const HOST: &str = "synq.li/";
const DELETE_STEP_MS: usize = 80;
const TYPE_STEP_MS: usize = 70;

/// The login hero's demo: one long link, how short it gets with a random
/// slug, and the same link once the slug is edited into a custom one.
pub struct LengthDemo {
    pub long_url: &'static str,
    pub long_len: usize,
    pub host: &'static str,
    pub random_slug: Vec<TimedChar>,
    pub random_len: usize,
    pub random_saving: usize,
    pub custom_slug: Vec<TimedChar>,
    pub custom_len: usize,
    pub custom_saving: usize,
}

/// One letter with the delay of its own animation, so letters can leave or
/// arrive one after another.
pub struct TimedChar {
    pub ch: char,
    pub delay_ms: usize,
}

pub fn login_demo() -> LengthDemo {
    let long_url = "https://link.synqloud.com/?utm_source=synq.li&utm_medium=short-link&utm_campaign=login-demo";
    let random_slug = "R3vt8w";
    let custom_slug = "shortlink";

    let long_len = char_len(long_url);
    let random_len = char_len(HOST) + char_len(random_slug);
    let custom_len = char_len(HOST) + char_len(custom_slug);

    LengthDemo {
        long_url,
        long_len,
        host: HOST,
        random_slug: deleted_backwards(random_slug),
        random_len,
        random_saving: percent_shorter(long_len, random_len),
        custom_slug: typed_forwards(custom_slug),
        custom_len,
        custom_saving: percent_shorter(long_len, custom_len),
    }
}

/// `"abc"` leaves from the end: delays 160, 80, 0 ms.
fn deleted_backwards(text: &str) -> Vec<TimedChar> {
    let last = char_len(text).saturating_sub(1);

    text.chars()
        .enumerate()
        .map(|(index, ch)| TimedChar {
            ch,
            delay_ms: (last - index) * DELETE_STEP_MS,
        })
        .collect()
}

/// `"abc"` arrives from the start: delays 0, 70, 140 ms.
fn typed_forwards(text: &str) -> Vec<TimedChar> {
    text.chars()
        .enumerate()
        .map(|(index, ch)| TimedChar {
            ch,
            delay_ms: index * TYPE_STEP_MS,
        })
        .collect()
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
    use super::{char_len, deleted_backwards, login_demo, percent_shorter, typed_forwards};

    fn delays(chars: &[super::TimedChar]) -> Vec<usize> {
        chars.iter().map(|c| c.delay_ms).collect()
    }

    #[test]
    fn lengths_count_characters_not_bytes() {
        assert_eq!(char_len("ตัวอย่าง.th"), 11);
    }

    #[test]
    fn the_demo_goes_from_91_to_14_then_17_characters() {
        let demo = login_demo();

        assert_eq!(
            (demo.long_len, demo.random_len, demo.custom_len),
            (91, 14, 17)
        );
        assert_eq!((demo.random_saving, demo.custom_saving), (85, 81));
    }

    #[test]
    fn the_random_slug_leaves_from_its_end_and_the_custom_one_types_in() {
        assert_eq!(delays(&deleted_backwards("abc")), [160, 80, 0]);
        assert_eq!(delays(&typed_forwards("abc")), [0, 70, 140]);
        assert!(deleted_backwards("").is_empty());
    }

    #[test]
    fn savings_round_to_the_nearest_percent() {
        assert_eq!(percent_shorter(91, 17), 81);
        assert_eq!(percent_shorter(200, 1), 100);
        assert_eq!(percent_shorter(3, 2), 33);
    }
}
