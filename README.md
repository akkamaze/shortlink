# shortlink

Short links at `link.synqloud.com`. Rust (Axum, tokio-postgres) with server-rendered Askama
pages and PostgreSQL.

Google sign-in works; the other sign-in buttons are drawn but not wired up yet.

## Run locally

Needs Docker and Rust 1.98.

```bash
cp .env.example .env
```

Fill in `.env`: the three Postgres passwords (the app and owner ones also go inside
`DATABASE_URL` and `MIGRATION_DATABASE_URL`), a `COOKIE_KEY` from
`openssl rand -base64 64 | tr -d '\n'` and a `DATA_KEY` from `openssl rand -base64 32`.
For sign-in without real Google, set `GOOGLE_ISSUER_URL=http://localhost:8080/default` and any
client id and secret.

```bash
docker compose --profile dev up -d
set -a && . ./.env && set +a
cargo run --bin migrate
cargo run
```

Open `http://localhost:3100`. "Continue with Google" goes to the mock provider; type any
username to sign in as `<username>@example.com`.

Open `http://localhost:3100`.

## Test

```bash
cargo test
```

Database tests run when `TEST_DATABASE_URL` (app role) and `TEST_MIGRATION_DATABASE_URL`
(owner role) point at a disposable database, for example the `shortlink_test` database that
`postgres/init` creates. Without them they skip.

## Database roles

`postgres/init/01-roles.sh` runs once, when the Postgres data directory is first created. The
superuser only bootstraps; `shortlink_owner` owns the schema and runs migrations;
`shortlink_app` is what the app connects as, with per-table grants from the migrations and no
right to create, alter or drop anything.

## Secrets and backups

The database holds only ciphertext and keyed hashes. That protects users only if the keys
never travel with the data.

- Keep `DATA_KEY` out of every backup that holds the database, and keep an offline copy of it:
  without it stored emails and names cannot be read, and returning users get new accounts.
- Give each process only its own secrets. Any secret can be read from a `*_FILE` path.
- Rotating `DATA_KEY` is not supported yet; a changed key signs everyone out.

## Layout

| Path | What it holds |
|---|---|
| `src/auth/` | Providers, OIDC flow, sessions, accounts |
| `src/crypto/` | Sealing personal fields and keyed lookups |
| `src/pages/` | Page handlers and their view data |
| `templates/` | `layouts/`, `pages/`, `components/`, `icons/` |
| `static/css/` | `tokens.css`, `base.css`, `fonts.css`, `components/`, `pages/` |
| `static/fonts/` | Self-hosted Inter and JetBrains Mono with their licences |
| `migrations/` | SQL run by the `migrate` binary as the owner role, never at app start |
| `postgres/init/` | One-time role and database bootstrap for a new Postgres data directory |
