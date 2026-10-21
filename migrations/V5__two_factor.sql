-- Optional two-factor sign-in with an authenticator app. The TOTP secret is
-- sealed with the data key; confirmed_at stays NULL until the first code is
-- typed. last_used_step stops a code from working twice. Too many wrong
-- codes set locked_until.

CREATE TABLE totp_factors (
    user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    secret_sealed bytea NOT NULL,
    confirmed_at timestamptz,
    last_used_step bigint,
    failed_attempts integer NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    locked_until timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- One-time recovery codes, stored only as keyed hashes.
CREATE TABLE recovery_codes (
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL CHECK (octet_length(code_hash) = 32),
    used_at timestamptz,
    PRIMARY KEY (user_id, code_hash)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON totp_factors TO shortlink_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON recovery_codes TO shortlink_app;
