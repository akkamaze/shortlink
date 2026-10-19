-- Personal fields are sealed with keys kept outside the database, and
-- identities are found by a keyed hash, so a dump holds no readable user data.

CREATE TABLE users (
    id uuid PRIMARY KEY,
    email_sealed bytea NOT NULL,
    display_name_sealed bytea,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE identities (
    lookup_hash bytea PRIMARY KEY CHECK (octet_length(lookup_hash) = 32),
    provider text NOT NULL,
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX identities_user_id_idx ON identities (user_id);

CREATE TABLE spaces (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id uuid NOT NULL UNIQUE REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);

CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

-- The app role gets only what each table needs; it cannot create, alter or drop anything.
GRANT SELECT, INSERT, UPDATE, DELETE ON users TO shortlink_app;
GRANT SELECT, INSERT ON identities TO shortlink_app;
GRANT SELECT, INSERT ON spaces TO shortlink_app;
GRANT SELECT, INSERT, DELETE ON sessions TO shortlink_app;
