use axum::{
    http::StatusCode,
    response::{IntoResponse, Redirect, Response},
};

/// Why a sign-in stopped. Details go to the log; the browser goes back to the
/// login page with only a fixed problem code.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("sign-in expired or was started in another tab")]
    Expired,
    #[error("the provider reported: {0}")]
    Cancelled(String),
    #[error("provider exchange or token check failed: {0}")]
    Provider(String),
    #[error("email is not verified by the provider")]
    EmailNotVerified,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

/// What the login page tells the person. `?problem=expired` shows
/// [`Problem::Expired`]; unknown codes show nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Problem {
    Expired,
    Cancelled,
    ProviderFailed,
    EmailNotVerified,
    ServerError,
}

impl AuthError {
    pub fn problem(&self) -> Problem {
        match self {
            AuthError::Expired => Problem::Expired,
            AuthError::Cancelled(_) => Problem::Cancelled,
            AuthError::Provider(_) => Problem::ProviderFailed,
            AuthError::EmailNotVerified => Problem::EmailNotVerified,
            AuthError::Internal(_) => Problem::ServerError,
        }
    }

    pub fn log(&self) {
        if self.problem().status().is_server_error() {
            tracing::error!(error = %self, "sign-in failed");
        } else {
            tracing::warn!(error = %self, "sign-in refused");
        }
    }
}

impl Problem {
    const ALL: [Problem; 5] = [
        Problem::Expired,
        Problem::Cancelled,
        Problem::ProviderFailed,
        Problem::EmailNotVerified,
        Problem::ServerError,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Problem::Expired => "expired",
            Problem::Cancelled => "cancelled",
            Problem::ProviderFailed => "provider",
            Problem::EmailNotVerified => "email-not-verified",
            Problem::ServerError => "server",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|problem| problem.code() == code)
    }

    pub fn status(self) -> StatusCode {
        match self {
            Problem::Expired | Problem::Cancelled => StatusCode::BAD_REQUEST,
            Problem::ProviderFailed => StatusCode::BAD_GATEWAY,
            Problem::EmailNotVerified => StatusCode::FORBIDDEN,
            Problem::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Problem::Expired => {
                "That sign-in took too long or was started in another tab. Please try again."
            }
            Problem::Cancelled => "Sign-in was cancelled.",
            Problem::ProviderFailed => {
                "We could not confirm your account with the provider. Please try again."
            }
            Problem::EmailNotVerified => "Your email is not verified with the provider yet.",
            Problem::ServerError => "Something went wrong on our side. Please try again.",
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        self.log();

        Redirect::to(&format!("/login?problem={}", self.problem().code())).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::Problem;

    #[test]
    fn every_problem_round_trips_through_its_code() {
        for problem in Problem::ALL {
            assert_eq!(Problem::from_code(problem.code()), Some(problem));
        }
        assert_eq!(Problem::from_code("<script>"), None);
    }
}
