#!/bin/sh
# Runs once, when the Postgres data directory is first created.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
  -v owner_password="$SHORTLINK_OWNER_PASSWORD" \
  -v app_password="$SHORTLINK_APP_PASSWORD" <<'SQL'
-- A failed statement is logged with its text by default; keep passwords out.
SET log_min_error_statement = panic;

CREATE ROLE shortlink_owner LOGIN PASSWORD :'owner_password';
CREATE ROLE shortlink_app LOGIN PASSWORD :'app_password';

CREATE DATABASE shortlink OWNER shortlink_owner;
CREATE DATABASE shortlink_test OWNER shortlink_owner;

REVOKE ALL ON DATABASE shortlink, shortlink_test FROM PUBLIC;
GRANT CONNECT ON DATABASE shortlink, shortlink_test TO shortlink_owner, shortlink_app;
REVOKE CONNECT, TEMPORARY ON DATABASE postgres, template1 FROM PUBLIC;
SQL

for db in shortlink shortlink_test; do
  psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$db" <<'SQL'
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO shortlink_app;
SQL
done
