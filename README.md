# shortlink

Short links at `link.synqloud.com`. Rust (Axum) with server-rendered Askama pages.

So far this is the login page only: every sign-in button is drawn but disabled.

## Run locally

Needs Rust 1.98.

```bash
cp .env.example .env
set -a && . ./.env && set +a
cargo run
```

Open `http://localhost:3100`.

## Test

```bash
cargo test
```

## Layout

| Path | What it holds |
|---|---|
| `src/pages/` | Page handlers and their view data |
| `templates/` | `layouts/`, `pages/`, `components/`, `icons/` |
| `static/css/` | `tokens.css`, `base.css`, `fonts.css`, `components/`, `pages/` |
| `static/fonts/` | Self-hosted Inter and JetBrains Mono with their licences |
