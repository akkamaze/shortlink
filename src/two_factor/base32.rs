const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding, the form authenticator apps read.
/// `b"foobar"` gives `"MZXW6YTBOI"`.
pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u16 = 0;
    let mut bits = 0;

    for byte in bytes {
        buffer = (buffer << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(ALPHABET[usize::from((buffer >> bits) & 31)]));
        }
    }
    if bits > 0 {
        out.push(char::from(
            ALPHABET[usize::from((buffer << (5 - bits)) & 31)],
        ));
    }

    out
}

/// The inverse of [`encode`]; `None` for any character outside the alphabet.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u16 = 0;
    let mut bits = 0;

    for byte in text.bytes() {
        let value = ALPHABET.iter().position(|letter| *letter == byte)?;
        buffer = (buffer << 5) | u16::try_from(value).expect("the alphabet has 32 letters");
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).expect("masked to one byte"));
        }
    }

    Some(out)
}

pub fn alphabet() -> &'static [u8; 32] {
    ALPHABET
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn matches_the_rfc_4648_examples_without_padding() {
        let cases = [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ];

        for (input, expected) in cases {
            assert_eq!(encode(input.as_bytes()), expected, "{input}");
            assert_eq!(
                decode(expected).as_deref(),
                Some(input.as_bytes()),
                "{expected}"
            );
        }
    }

    #[test]
    fn decoding_refuses_letters_outside_the_alphabet() {
        assert_eq!(decode("MZXW1"), None, "1 is not base32");
        assert_eq!(decode("mzxw6"), None, "only upper case");
    }
}
