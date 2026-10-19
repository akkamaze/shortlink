# shortlink

Short links at `link.synqloud.com`. Rust (Axum, tokio-postgres) with server-rendered Askama
pages and PostgreSQL.

So far this is the login page only: every sign-in button is drawn but disabled.

## Run locally

Needs Docker and Rust 1.98.

```bash
cp .env.example .env
```

Fill in the three Postgres passwords in `.env`; the owner one also goes inside
`MIGRATION_DATABASE_URL`.

```bash
docker compose up -d
set -a && . ./.env && set +a
cargo run --bin migrate
cargo run
```

Open `http://localhost:3100`.

## Test

```bash
cargo test
```

## Database roles

`postgres/init/01-roles.sh` runs once, when the Postgres data directory is first created. The
superuser only bootstraps; `shortlink_owner` owns the schema and runs migrations;
`shortlink_app` is what the app connects as, with per-table grants from the migrations and no
right to create, alter or drop anything.

## Layout

| Path | What it holds |
|---|---|
| `src/pages/` | Page handlers and their view data |
| `templates/` | `layouts/`, `pages/`, `components/`, `icons/` |
| `static/css/` | `tokens.css`, `base.css`, `fonts.css`, `components/`, `pages/` |
| `static/fonts/` | Self-hosted Inter and JetBrains Mono with their licences |
| `migrations/` | SQL run by the `migrate` binary as the owner role, never at app start |
| `postgres/init/` | One-time role and database bootstrap for a new Postgres data directory |
