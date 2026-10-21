use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

pub const STEP_SECONDS: u64 = 30;
pub const SECRET_LEN: usize = 20;
const DIGITS: u32 = 6;

/// A code typed one step early or late still counts, to allow for a phone
/// clock that drifts or a code typed as it changes.
const ALLOWED_DRIFT: u64 = 1;

pub fn step_at(unix_seconds: u64) -> u64 {
    unix_seconds / STEP_SECONDS
}

/// RFC 6238 TOTP with HMAC-SHA1 and six digits, as authenticator apps
/// compute it by default.
pub fn code_at(secret: &[u8], step: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&step.to_be_bytes());
    let digest = mac.finalize().into_bytes();

    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let window: [u8; 4] = digest[offset..offset + 4]
        .try_into()
        .expect("the offset leaves four bytes");

    (u32::from_be_bytes(window) & 0x7fff_ffff) % 10u32.pow(DIGITS)
}

/// The step a typed code belongs to, if it is within the allowed drift of
/// `now_step`. Spaces are ignored; anything but six digits never matches.
pub fn matching_step(secret: &[u8], typed: &str, now_step: u64) -> Option<u64> {
    let digits: String = typed.chars().filter(|c| !c.is_whitespace()).collect();
    if digits.len() != DIGITS as usize || !digits.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let code: u32 = digits.parse().ok()?;

    (now_step.saturating_sub(ALLOWED_DRIFT)..=now_step + ALLOWED_DRIFT)
        .find(|step| code_at(secret, *step) == code)
}

/// The `otpauth://` link a QR code carries. The label holds no personal data.
pub fn provisioning_uri(secret_base32: &str) -> String {
    format!(
        "otpauth://totp/shortlink?secret={secret_base32}&issuer=shortlink\
         &algorithm=SHA1&digits={DIGITS}&period={STEP_SECONDS}"
    )
}

#[cfg(test)]
mod tests {
    use super::{code_at, matching_step, step_at};

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn matches_the_rfc_6238_sha1_vectors() {
        // RFC 6238 appendix B gives eight digits; apps show the last six.
        let vectors = [
            (59, 287_082),
            (1_111_111_109, 81_804),
            (1_111_111_111, 50_471),
            (1_234_567_890, 5_924),
            (2_000_000_000, 279_037),
        ];

        for (time, code) in vectors {
            assert_eq!(code_at(RFC_SECRET, step_at(time)), code, "T = {time}");
        }
    }

    #[test]
    fn accepts_one_step_of_drift_and_no_more() {
        let now = step_at(1_234_567_890);
        let typed = |step| format!("{:06}", code_at(RFC_SECRET, step));

        assert_eq!(matching_step(RFC_SECRET, &typed(now), now), Some(now));
        assert_eq!(
            matching_step(RFC_SECRET, &typed(now - 1), now),
            Some(now - 1)
        );
        assert_eq!(
            matching_step(RFC_SECRET, &typed(now + 1), now),
            Some(now + 1)
        );
        assert_eq!(matching_step(RFC_SECRET, &typed(now - 2), now), None);
    }

    #[test]
    fn ignores_spaces_and_refuses_anything_but_six_digits() {
        let now = step_at(1_234_567_890);
        let code = format!("{:06}", code_at(RFC_SECRET, now));

        assert_eq!(
            matching_step(RFC_SECRET, &format!("{} {}", &code[..3], &code[3..]), now),
            Some(now)
        );
        for typed in ["", "12345", "1234567", "12a456", "-12345"] {
            assert_eq!(matching_step(RFC_SECRET, typed, now), None, "{typed}");
        }
    }
}
