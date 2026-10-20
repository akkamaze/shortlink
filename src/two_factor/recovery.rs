use super::base32::alphabet;

pub const CODES: usize = 10;
const HALF: usize = 5;

/// Ten one-time codes such as `K7QXM-2RV4T`: 50 random bits each, shown once
/// and stored only as keyed hashes.
pub fn generate() -> Vec<String> {
    (0..CODES).map(|_| code()).collect()
}

/// Each random byte keeps its low five bits; 256 is a multiple of 32, so
/// every character is equally likely.
fn code() -> String {
    let mut bytes = [0u8; HALF * 2];
    rand::fill(&mut bytes);

    let mut chars: String = bytes
        .iter()
        .map(|byte| char::from(alphabet()[usize::from(byte & 31)]))
        .collect();
    chars.insert(HALF, '-');
    chars
}

/// `" k7qxm 2rv4t "` and `"K7QXM-2RV4T"` give the same `"K7QXM2RV4T"`.
pub fn normalize(typed: &str) -> String {
    typed
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{CODES, generate, normalize};

    #[test]
    fn codes_are_distinct_and_shaped_like_xxxxx_xxxxx() {
        let codes = generate();

        assert_eq!(codes.len(), CODES);
        assert_eq!(codes.iter().collect::<HashSet<_>>().len(), CODES);
        for code in &codes {
            assert_eq!(code.len(), 11, "{code}");
            assert_eq!(&code[5..6], "-", "{code}");
        }
    }

    #[test]
    fn typed_codes_ignore_case_spaces_and_dashes() {
        assert_eq!(normalize(" k7qxm 2rv4t "), "K7QXM2RV4T");
        assert_eq!(normalize("K7QXM-2RV4T"), "K7QXM2RV4T");
    }
}
