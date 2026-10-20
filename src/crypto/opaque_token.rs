use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};

const TOKEN_BYTES: usize = 32;

/// A random secret for a cookie. Only its SHA-256 hash is stored, so a
/// database leak cannot be replayed.
pub struct OpaqueToken {
    pub raw: String,
    pub hash: Vec<u8>,
}

impl OpaqueToken {
    pub fn generate() -> Self {
        let mut bytes = [0u8; TOKEN_BYTES];
        rand::fill(&mut bytes);

        Self {
            raw: URL_SAFE_NO_PAD.encode(bytes),
            hash: Sha256::digest(bytes).to_vec(),
        }
    }
}

/// `None` for anything that is not exactly 32 bytes of URL-safe base64, so
/// junk cookies never reach the database.
pub fn hash_of(raw: &str) -> Option<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD.decode(raw).ok()?;
    (bytes.len() == TOKEN_BYTES).then(|| Sha256::digest(&bytes).to_vec())
}

#[cfg(test)]
mod tests {
    use super::{OpaqueToken, hash_of};

    #[test]
    fn the_cookie_value_hashes_to_the_stored_hash() {
        let first = OpaqueToken::generate();
        let second = OpaqueToken::generate();

        assert_ne!(first.raw, second.raw);
        assert_eq!(hash_of(&first.raw), Some(first.hash));
    }

    #[test]
    fn malformed_tokens_are_rejected_before_the_database() {
        assert_eq!(hash_of(""), None);
        assert_eq!(hash_of("not base64 !"), None);
        assert_eq!(hash_of("c2hvcnQ"), None);
    }
}
