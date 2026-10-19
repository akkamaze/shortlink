//! Runs against a real Postgres. Set `TEST_DATABASE_URL` to the app role and
//! `TEST_MIGRATION_DATABASE_URL` to the owner role of a disposable database,
//! for example the compose `shortlink_test`.

use std::fmt::Write;

use axum_extra::extract::cookie::CookieJar;
use shortlink::{
    auth::{
        accounts::{VerifiedIdentity, sign_in},
        provider::Provider,
        session,
    },
    crypto::DataKeys,
    db,
};

static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

async fn test_pool() -> Option<deadpool_postgres::Pool> {
    let (Ok(url), Ok(owner_url)) = (
        std::env::var("TEST_DATABASE_URL"),
        std::env::var("TEST_MIGRATION_DATABASE_URL"),
    ) else {
        eprintln!("skipped: TEST_DATABASE_URL or TEST_MIGRATION_DATABASE_URL is not set");
        return None;
    };

    MIGRATED
        .get_or_init(|| async {
            db::run_migrations(&owner_url)
                .await
                .expect("migrations apply");
        })
        .await;
    Some(db::connect_pool(&url).expect("pool"))
}

fn keys() -> DataKeys {
    DataKeys::from_master(&[42u8; 32]).unwrap()
}

fn identity(subject: &str, email: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        provider: Provider::Google,
        subject: subject.to_owned(),
        email: email.to_owned(),
        display_name: Some("Ann".to_owned()),
    }
}

#[tokio::test]
async fn signing_in_twice_reuses_the_user_and_its_single_space() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let subject = uuid::Uuid::new_v4().to_string();

    let first = sign_in(&pool, &keys(), &identity(&subject, "ann@example.com"))
        .await
        .unwrap();
    let second = sign_in(&pool, &keys(), &identity(&subject, "ann@new.example"))
        .await
        .unwrap();

    let client = pool.get().await.unwrap();
    let spaces: i64 = client
        .query_one(
            "SELECT count(*) FROM spaces WHERE owner_user_id = $1",
            &[&first],
        )
        .await
        .unwrap()
        .get(0);
    let jar = CookieJar::new().add(
        session::create(&pool, first)
            .await
            .unwrap()
            .into_cookie(false),
    );
    let email = session::current_user(&pool, &keys(), &jar)
        .await
        .unwrap()
        .unwrap()
        .email;

    assert_eq!(first, second);
    assert_eq!(spaces, 1);
    assert_eq!(email, "ann@new.example");
}

#[tokio::test]
async fn concurrent_first_sign_ins_produce_one_user() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let subject = uuid::Uuid::new_v4().to_string();
    let email = format!("{subject}@example.com");

    let racers = (0..8).map(|_| {
        let pool = pool.clone();
        let identity = identity(&subject, &email);
        tokio::spawn(async move { sign_in(&pool, &keys(), &identity).await.unwrap() })
    });
    let ids = join_all(racers).await;

    let client = pool.get().await.unwrap();
    let users: i64 = client
        .query_one(
            "SELECT count(*) FROM identities i JOIN users u ON u.id = i.user_id WHERE i.user_id = $1",
            &[&ids[0]],
        )
        .await
        .unwrap()
        .get(0);

    assert!(ids.iter().all(|id| *id == ids[0]));
    assert_eq!(users, 1);
}

#[tokio::test]
async fn session_cookie_finds_the_user_until_deleted() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let subject = uuid::Uuid::new_v4().to_string();
    let user_id = sign_in(&pool, &keys(), &identity(&subject, "bob@example.com"))
        .await
        .unwrap();

    let token = session::create(&pool, user_id).await.unwrap();
    let jar = CookieJar::new().add(token.into_cookie(false));

    let found = session::current_user(&pool, &keys(), &jar)
        .await
        .unwrap()
        .map(|user| user.id);
    session::delete(&pool, &jar).await.unwrap();
    let after_logout = session::current_user(&pool, &keys(), &jar).await.unwrap();

    assert_eq!(found, Some(user_id));
    assert!(after_logout.is_none());
}

async fn join_all<T: Send + 'static>(
    handles: impl Iterator<Item = tokio::task::JoinHandle<T>>,
) -> Vec<T> {
    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.unwrap());
    }
    results
}

#[tokio::test]
async fn a_database_dump_holds_no_readable_personal_data() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let subject = format!("sub-{}", uuid::Uuid::new_v4());
    let email = format!("{subject}@leakcheck.example");
    let name = format!("Leakcheck {subject}");

    let user_id = sign_in(
        &pool,
        &keys(),
        &VerifiedIdentity {
            provider: Provider::Google,
            subject: subject.clone(),
            email: email.clone(),
            display_name: Some(name.clone()),
        },
    )
    .await
    .unwrap();
    session::create(&pool, user_id).await.unwrap();

    let client = pool.get().await.unwrap();
    let mut dump = String::new();
    for table in ["users", "identities", "spaces", "sessions"] {
        for row in client
            .query(&format!("SELECT row_to_json(t)::text FROM {table} t"), &[])
            .await
            .unwrap()
        {
            dump.push_str(row.get::<_, &str>(0));
        }
    }

    for secret in [&subject, &email, &name] {
        let as_hex = secret.bytes().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        });
        assert!(
            !dump.contains(secret.as_str()),
            "{secret} is readable in the dump"
        );
        assert!(!dump.contains(&as_hex), "{secret} is stored as raw bytes");
    }
}

#[tokio::test]
async fn the_app_role_cannot_change_the_schema_or_migration_history() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let client = pool.get().await.unwrap();

    for statement in [
        "DROP TABLE sessions",
        "CREATE TABLE intruder (id int)",
        "ALTER TABLE users ADD COLUMN extra text",
        "DELETE FROM identities",
        "UPDATE identities SET user_id = user_id",
        "DELETE FROM spaces",
        "UPDATE sessions SET expires_at = now()",
        "DELETE FROM refinery_schema_history",
        "SELECT * FROM refinery_schema_history",
    ] {
        let error = client.batch_execute(statement).await.expect_err(statement);
        assert_eq!(
            error.code(),
            Some(&tokio_postgres::error::SqlState::INSUFFICIENT_PRIVILEGE),
            "{statement}: {error}"
        );
    }
}

async fn session_rows(pool: &deadpool_postgres::Pool, user_id: uuid::Uuid) -> i64 {
    pool.get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM sessions WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .unwrap()
        .get(0)
}

#[tokio::test]
async fn a_profile_that_cannot_be_opened_signs_the_session_out() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let subject = uuid::Uuid::new_v4().to_string();
    let user_id = sign_in(&pool, &keys(), &identity(&subject, "rotated@example.com"))
        .await
        .unwrap();
    let jar = CookieJar::new().add(
        session::create(&pool, user_id)
            .await
            .unwrap()
            .into_cookie(false),
    );
    let other_keys = DataKeys::from_master(&[9u8; 32]).unwrap();

    let user = session::current_user(&pool, &other_keys, &jar)
        .await
        .unwrap();

    assert!(user.is_none());
    assert_eq!(session_rows(&pool, user_id).await, 0);
}

#[tokio::test]
async fn cleanup_removes_expired_sessions_and_keeps_live_ones() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let subject = uuid::Uuid::new_v4().to_string();
    let user_id = sign_in(&pool, &keys(), &identity(&subject, "cleanup@example.com"))
        .await
        .unwrap();
    let live = CookieJar::new().add(
        session::create(&pool, user_id)
            .await
            .unwrap()
            .into_cookie(false),
    );

    let client = pool.get().await.unwrap();
    client
        .execute(
            "INSERT INTO sessions (token_hash, user_id, created_at, expires_at)
             VALUES (sha256(gen_random_uuid()::text::bytea), $1, now() - interval '2 days', now() - interval '1 day')",
            &[&user_id],
        )
        .await
        .unwrap();

    session::delete_expired(&pool).await.unwrap();
    let expired_left: i64 = client
        .query_one(
            "SELECT count(*) FROM sessions WHERE user_id = $1 AND expires_at <= now()",
            &[&user_id],
        )
        .await
        .unwrap()
        .get(0);
    let still_signed_in = session::current_user(&pool, &keys(), &live).await.unwrap();

    assert_eq!(expired_left, 0);
    assert!(still_signed_in.is_some());
    assert_eq!(
        session::delete_expired(&pool).await.unwrap(),
        0,
        "a second run changes nothing"
    );
}
