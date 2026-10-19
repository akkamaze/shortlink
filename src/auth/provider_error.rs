use openidconnect::{ClaimsVerificationError, ErrorResponse, RequestTokenError};

/// Library error text can carry token claims such as the subject, so only a
/// fixed description of the failure reaches the log.
pub fn describe_claims_error(error: &ClaimsVerificationError) -> &'static str {
    match error {
        ClaimsVerificationError::Expired(_) => "ID token expired",
        ClaimsVerificationError::InvalidAudience(_) => "ID token audience mismatch",
        ClaimsVerificationError::InvalidAuthContext(_) => "ID token auth context rejected",
        ClaimsVerificationError::InvalidAuthTime(_) => "ID token auth time rejected",
        ClaimsVerificationError::InvalidIssuer(_) => "ID token issuer mismatch",
        ClaimsVerificationError::InvalidNonce(_) => "ID token nonce mismatch",
        ClaimsVerificationError::InvalidSubject(_) => "ID token subject rejected",
        ClaimsVerificationError::SignatureVerification(_) => "ID token signature invalid",
        ClaimsVerificationError::Unsupported(_) => "ID token uses an unsupported feature",
        _ => "ID token check failed",
    }
}

pub fn describe_token_error<RE, T>(error: &RequestTokenError<RE, T>) -> &'static str
where
    RE: std::error::Error + 'static,
    T: ErrorResponse + 'static,
{
    match error {
        RequestTokenError::ServerResponse(_) => "provider rejected the authorization code",
        RequestTokenError::Request(_) => "token request did not reach the provider",
        RequestTokenError::Parse(..) => "provider sent an unreadable token response",
        RequestTokenError::Other(_) => "token exchange failed",
    }
}

/// The `error` value in a callback is chosen by whoever crafted the URL.
/// OAuth error codes are short lowercase words; anything else is replaced.
pub fn callback_error_code(raw: &str) -> &str {
    let is_code = (1..=40).contains(&raw.len())
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_');

    if is_code { raw } else { "unrecognised_error" }
}

#[cfg(test)]
mod tests {
    use openidconnect::ClaimsVerificationError;

    use super::{callback_error_code, describe_claims_error};

    #[test]
    fn claims_errors_never_carry_the_claim_values() {
        let error = ClaimsVerificationError::InvalidSubject("109876543210987654321".to_owned());

        assert!(
            error.to_string().contains("109876543210987654321"),
            "the library text leaks it"
        );
        assert!(!describe_claims_error(&error).contains("1098765"));
    }

    #[test]
    fn callback_error_codes_pass_and_anything_else_is_replaced() {
        assert_eq!(callback_error_code("access_denied"), "access_denied");
        assert_eq!(
            callback_error_code("x\nINFO forged log line"),
            "unrecognised_error"
        );
        assert_eq!(callback_error_code(""), "unrecognised_error");
        assert_eq!(callback_error_code(&"a".repeat(41)), "unrecognised_error");
    }
}
