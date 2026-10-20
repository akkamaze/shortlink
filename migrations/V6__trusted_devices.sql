-- Browsers that skip the two-factor code for a while after the person ticks
-- "Trust this device". Only a hash of the cookie token is stored.

CREATE TABLE trusted_devices (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);

CREATE INDEX trusted_devices_user_id_idx ON trusted_devices (user_id);
CREATE INDEX trusted_devices_expires_at_idx ON trusted_devices (expires_at);

GRANT SELECT, INSERT, DELETE ON trusted_devices TO shortlink_app;
