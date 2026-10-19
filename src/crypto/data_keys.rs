use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, Generate, KeyInit, Payload},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

const SEALED_VERSION: u8 = 1;
const NONCE_LEN: usize = 24;
const MIN_MASTER_LEN: usize = 32;

/// Keys for data at rest, derived from one master key that lives outside
/// the database and its backups.
#[derive(Clone)]
pub struct DataKeys {
    field_cipher: XChaCha20Poly1305,
    lookup_key: [u8; 64],
}

/// Which column a sealed value belongs to. Together with the row id it is
/// bound into the ciphertext, so a value copied to another row or column
/// fails to open.
#[derive(Debug, Clone, Copy)]
pub enum Field {
    UserEmail,
    UserDisplayName,
}

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("the master key must be at least {MIN_MASTER_LEN} bytes")]
    TooShort,
}

#[derive(Debug, thiserror::Error)]
#[error("sealed value is malformed, was tampered with, or belongs to another row")]
pub struct OpenError;

impl DataKeys {
    pub fn from_master(master: &[u8]) -> Result<Self, KeyError> {
        if master.len() < MIN_MASTER_LEN {
            return Err(KeyError::TooShort);
        }

        let hkdf = Hkdf::<Sha256>::new(Some(b"shortlink data keys"), master);

        Ok(Self {
            field_cipher: XChaCha20Poly1305::new(
                &derive::<32>(&hkdf, b"field encryption v1").into(),
            ),
            lookup_key: derive::<64>(&hkdf, b"lookup hmac v1"),
        })
    }

    /// `version || nonce || ciphertext`, with a fresh random nonce each time.
    pub fn seal(&self, plaintext: &str, field: Field, row: Uuid) -> Vec<u8> {
        let nonce = XNonce::generate();
        let aad = associated_data(SEALED_VERSION, field, row);
        let ciphertext = self
            .field_cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: &aad,
                },
            )
            .expect("XChaCha20-Poly1305 encryption of a short field cannot fail");

        [&[SEALED_VERSION][..], nonce.as_slice(), &ciphertext].concat()
    }

    pub fn open(&self, sealed: &[u8], field: Field, row: Uuid) -> Result<String, OpenError> {
        let (&version, rest) = sealed.split_first().ok_or(OpenError)?;
        if version != SEALED_VERSION || rest.len() < NONCE_LEN {
            return Err(OpenError);
        }

        let (nonce, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).map_err(|_| OpenError)?;
        let aad = associated_data(SEALED_VERSION, field, row);
        let plaintext = self
            .field_cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| OpenError)?;

        String::from_utf8(plaintext).map_err(|_| OpenError)
    }

    /// Stable keyed hash for finding a row without storing the value.
    /// `("google", "1234")` always gives the same 32 bytes under one master key.
    /// The namespace is length-prefixed so no two inputs share bytes.
    pub fn lookup_hash(&self, namespace: &str, value: &str) -> Vec<u8> {
        let namespace_len = u32::try_from(namespace.len()).expect("namespace is a short label");

        let mut mac = Hmac::<Sha256>::new(&self.lookup_key.into());
        mac.update(&namespace_len.to_be_bytes());
        mac.update(namespace.as_bytes());
        mac.update(value.as_bytes());

        mac.finalize().into_bytes().to_vec()
    }
}

fn derive<const LEN: usize>(hkdf: &Hkdf<Sha256>, label: &[u8]) -> [u8; LEN] {
    let mut key = [0u8; LEN];
    hkdf.expand(label, &mut key)
        .expect("32 and 64 bytes are valid HKDF-SHA256 output lengths");
    key
}

fn associated_data(version: u8, field: Field, row: Uuid) -> Vec<u8> {
    let label: &[u8] = match field {
        Field::UserEmail => b"users.email",
        Field::UserDisplayName => b"users.display_name",
    };

    [&[version][..], label, &[0], row.as_bytes()].concat()
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use super::{DataKeys, Field};

    fn keys() -> DataKeys {
        DataKeys::from_master(&[7u8; 32]).unwrap()
    }

    #[test]
    fn sealed_value_opens_only_for_its_own_row_and_field() {
        let keys = keys();
        let ann = Uuid::new_v4();
        let bob = Uuid::new_v4();

        let sealed = keys.seal("ann@example.com", Field::UserEmail, ann);

        assert_eq!(
            keys.open(&sealed, Field::UserEmail, ann).unwrap(),
            "ann@example.com"
        );
        assert!(keys.open(&sealed, Field::UserEmail, bob).is_err());
        assert!(keys.open(&sealed, Field::UserDisplayName, ann).is_err());
    }

    #[test]
    fn ciphertext_hides_the_plaintext_and_changes_every_time() {
        let keys = keys();
        let row = Uuid::new_v4();

        let first = keys.seal("ann@example.com", Field::UserEmail, row);
        let second = keys.seal("ann@example.com", Field::UserEmail, row);

        assert_ne!(first, second);
        assert!(!first.windows(3).any(|w| w == b"ann"));
    }

    #[test]
    fn tampered_or_truncated_values_fail_to_open() {
        let keys = keys();
        let row = Uuid::new_v4();
        let mut sealed = keys.seal("ann@example.com", Field::UserEmail, row);

        let last = sealed.len() - 1;
        sealed[last] ^= 1;

        assert!(keys.open(&sealed, Field::UserEmail, row).is_err());
        assert!(keys.open(&sealed[..10], Field::UserEmail, row).is_err());
        assert!(keys.open(&[], Field::UserEmail, row).is_err());
    }

    #[test]
    fn another_master_key_cannot_open_or_match_lookups() {
        let row = Uuid::new_v4();
        let other = DataKeys::from_master(&[8u8; 32]).unwrap();
        let sealed = keys().seal("ann@example.com", Field::UserEmail, row);

        assert!(other.open(&sealed, Field::UserEmail, row).is_err());
        assert_ne!(
            keys().lookup_hash("google", "1234"),
            other.lookup_hash("google", "1234")
        );
    }

    #[test]
    fn lookup_hash_is_stable_and_separates_namespaces() {
        let keys = keys();

        assert_eq!(
            keys.lookup_hash("google", "1234"),
            keys.lookup_hash("google", "1234")
        );
        assert_ne!(
            keys.lookup_hash("google", "1234"),
            keys.lookup_hash("line", "1234")
        );
        assert_ne!(
            keys.lookup_hash("google", "12\u{0}34"),
            keys.lookup_hash("google\u{0}12", "34")
        );
        assert_eq!(keys.lookup_hash("google", "1234").len(), 32);
    }

    #[test]
    fn short_master_keys_are_rejected() {
        assert!(DataKeys::from_master(&[1u8; 31]).is_err());
    }
}
