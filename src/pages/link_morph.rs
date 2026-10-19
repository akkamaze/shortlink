const LONG_CHAR_STEP_MS: u32 = 7;
const SHORT_CHAR_STEP_MS: u32 = 35;
const SLOT_GAP_MS: u32 = 4000;

/// One long link that shrinks into its short form on the login card. Two
/// slots share an 8 s loop, each starting 4 s after the previous one.
pub struct LinkMorph {
    pub delay_ms: u32,
    pub long_caption: String,
    pub short_caption: String,
    pub long_chars: Vec<TimedChar>,
    pub short_chars: Vec<TimedChar>,
}

pub struct TimedChar {
    pub ch: char,
    pub delay_ms: u32,
    pub dim: bool,
}

impl LinkMorph {
    /// The long link vanishes from its last character backwards, then the
    /// short link types in from the first character forwards.
    ///
    /// Slot 1 of `"abc"` → `"s.li/" + "x"`: long delays 4014, 4007, 4000 ms;
    /// short delays 4000 to 4175 ms, with `s.li/` dimmed.
    pub fn new(slot: u32, long_url: &str, short_host: &str, short_path: &str) -> Self {
        let delay_ms = slot * SLOT_GAP_MS;
        let long_len = char_count(long_url);

        let long_chars = long_url
            .chars()
            .zip(0u32..)
            .map(|(ch, index)| TimedChar {
                ch,
                delay_ms: delay_ms + (long_len - 1 - index) * LONG_CHAR_STEP_MS,
                dim: false,
            })
            .collect();

        let host_len = char_count(short_host);
        let short_chars = short_host
            .chars()
            .chain(short_path.chars())
            .zip(0u32..)
            .map(|(ch, index)| TimedChar {
                ch,
                delay_ms: delay_ms + index * SHORT_CHAR_STEP_MS,
                dim: index < host_len,
            })
            .collect();

        Self {
            delay_ms,
            long_caption: format!("Long link · {long_len} characters"),
            short_caption: format!(
                "Short link · {} characters",
                host_len + char_count(short_path)
            ),
            long_chars,
            short_chars,
        }
    }
}

pub fn login_demos() -> Vec<LinkMorph> {
    vec![
        LinkMorph::new(
            0,
            "https://link.synqloud.com/?utm_source=synq.li&utm_medium=short-link&utm_campaign=login-demo",
            "synq.li/",
            "shortlink",
        ),
        LinkMorph::new(
            1,
            "https://link.synqloud.com/?utm_source=synq.li&utm_medium=random-slug&utm_campaign=login-demo",
            "synq.li/",
            "R3vt8w",
        ),
    ]
}

fn char_count(text: &str) -> u32 {
    u32::try_from(text.chars().count()).expect("demo text is short")
}

#[cfg(test)]
mod tests {
    use super::LinkMorph;

    #[test]
    fn long_link_leaves_backwards_and_short_link_types_forwards() {
        let morph = LinkMorph::new(1, "abc", "s.li/", "x");

        let long: Vec<u32> = morph.long_chars.iter().map(|c| c.delay_ms).collect();
        let short: Vec<u32> = morph.short_chars.iter().map(|c| c.delay_ms).collect();
        let dimmed: String = morph
            .short_chars
            .iter()
            .filter(|c| c.dim)
            .map(|c| c.ch)
            .collect();

        assert_eq!(morph.delay_ms, 4000);
        assert_eq!(long, [4014, 4007, 4000]);
        assert_eq!(short, [4000, 4035, 4070, 4105, 4140, 4175]);
        assert_eq!(dimmed, "s.li/");
    }

    #[test]
    fn captions_count_characters_not_bytes() {
        let morph = LinkMorph::new(0, "https://ตัวอย่าง.th", "s.li/", "ไทย");

        assert_eq!(morph.long_caption, "Long link · 19 characters");
        assert_eq!(morph.short_caption, "Short link · 8 characters");
    }
}
