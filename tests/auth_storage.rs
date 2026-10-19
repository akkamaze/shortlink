//! Runs against a real Postgres. Set `TEST_DATABASE_URL` to the app role and
//! `TEST_MIGRATION_DATABASE_URL` to the owner role of a disposable database,
//! for example the compose `shortlink_test`.

use std::fmt::Write;

use axum_extra::extract::cookie::CookieJar;
use shortlink::{
    auth::{
        accounts::{self, Attach, ProviderEmail, SignIn, VerifiedIdentity, sign_in},
        picture::PictureUrl,
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
        email: Some(ProviderEmail {
            address: email.to_owned(),
            verified: true,
        }),
        display_name: Some("Ann".to_owned()),
        picture: None,
    }
}

fn line_identity(subject: &str) -> VerifiedIdentity {
    VerifiedIdentity {
        provider: Provider::Line,
        subject: subject.to_owned(),
        email: None,
        display_name: Some("Ann on LINE".to_owned()),
        picture: PictureUrl::parse(&format!("https://profile.line-scdn.net/{subject}")),
    }
}

async fn signed(pool: &deadpool_postgres::Pool, identity: &VerifiedIdentity) -> uuid::Uuid {
    match sign_in(pool, &keys(), identity).await.unwrap() {
        SignIn::Signed(user_id) => user_id,
        SignIn::EmailTaken { .. } => panic!("expected a sign-in, the email was taken"),
    }
}

fn fresh_subject() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn session_jar(token: session::SessionToken) -> CookieJar {
    CookieJar::new().add(token.into_cookie(false))
}

#[tokio::test]
async fn signing_in_twice_reuses_the_user_and_its_single_space() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let subject = uuid::Uuid::new_v4().to_string();

    let first = signed(
        &pool,
        &identity(&subject, &format!("{subject}-ann@example.com")),
    )
    .await;
    let second = signed(
        &pool,
        &identity(&subject, &format!("{subject}-ann@new.example")),
    )
    .await;

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
    assert_eq!(
        email.as_deref(),
        Some(format!("{subject}-ann@new.example").as_str())
    );
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
        tokio::spawn(async move { signed(&pool, &identity).await })
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
    let user_id = signed(
        &pool,
        &identity(&subject, &format!("{subject}-bob@example.com")),
    )
    .await;

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
    let picture = format!("https://profile.line-scdn.net/{subject}-pic");

    let user_id = signed(
        &pool,
        &VerifiedIdentity {
            provider: Provider::Google,
            subject: subject.clone(),
            email: Some(ProviderEmail {
                address: email.clone(),
                verified: true,
            }),
            display_name: Some(name.clone()),
            picture: PictureUrl::parse(&picture),
        },
    )
    .await;
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

    for secret in [&subject, &email, &name, &picture] {
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
    let user_id = signed(
        &pool,
        &identity(&subject, &format!("{subject}-rotated@example.com")),
    )
    .await;
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
    let user_id = signed(
        &pool,
        &identity(&subject, &format!("{subject}-cleanup@example.com")),
    )
    .await;
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

#[tokio::test]
async fn a_line_account_keeps_its_name_and_picture_and_has_no_email() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let line = line_identity(&fresh_subject());

    let user_id = signed(&pool, &line).await;
    let jar = session_jar(session::create(&pool, user_id).await.unwrap());
    let user = session::current_user(&pool, &keys(), &jar)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user.email, None);
    assert_eq!(user.display_name.as_deref(), Some("Ann on LINE"));
    assert_eq!(user.picture, line.picture);
}

#[tokio::test]
async fn google_and_line_sign_ins_are_separate_accounts() {
    let Some(pool) = test_pool().await else {
        return;
    };

    let via_google = signed(&pool, &identity(&fresh_subject(), &fresh_email())).await;
    let via_line = signed(&pool, &line_identity(&fresh_subject())).await;

    assert_ne!(via_google, via_line);
}

#[tokio::test]
async fn signing_in_again_replaces_the_name_and_picture() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let subject = fresh_subject();
    let user_id = signed(&pool, &line_identity(&subject)).await;

    let renamed = VerifiedIdentity {
        display_name: Some("Ann Lee".to_owned()),
        picture: None,
        ..line_identity(&subject)
    };
    signed(&pool, &renamed).await;
    let jar = session_jar(session::create(&pool, user_id).await.unwrap());
    let user = session::current_user(&pool, &keys(), &jar)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(user.display_name.as_deref(), Some("Ann Lee"));
    assert_eq!(user.picture, None, "a picture removed at LINE is gone here");
}

fn claimed_email(provider: Provider, address: &str, verified: bool) -> VerifiedIdentity {
    VerifiedIdentity {
        provider,
        subject: fresh_subject(),
        email: Some(ProviderEmail {
            address: address.to_owned(),
            verified,
        }),
        display_name: None,
        picture: None,
    }
}

fn fresh_email() -> String {
    format!("{}@example.com", fresh_subject())
}

#[tokio::test]
async fn a_new_sign_in_with_a_taken_email_waits_until_the_owner_adds_it() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let email = fresh_email();
    let owner = signed(&pool, &identity(&fresh_subject(), &email)).await;
    let newcomer = claimed_email(Provider::Line, &email.to_uppercase(), false);

    let first_try = sign_in(&pool, &keys(), &newcomer).await.unwrap();
    let added = accounts::attach(&pool, &keys(), owner, &newcomer)
        .await
        .unwrap();
    let next_time = sign_in(&pool, &keys(), &newcomer).await.unwrap();

    assert_eq!(first_try, SignIn::EmailTaken { holder: owner });
    assert_eq!(added, Attach::Attached);
    assert_eq!(next_time, SignIn::Signed(owner));
    assert_eq!(
        accounts::sign_in_providers(&pool, owner).await.unwrap(),
        [Provider::Google, Provider::Line]
    );
}

#[tokio::test]
async fn a_sign_in_that_opens_another_account_cannot_be_added() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let mine = signed(&pool, &identity(&fresh_subject(), &fresh_email())).await;
    let theirs = line_identity(&fresh_subject());
    let their_account = signed(&pool, &theirs).await;

    let added = accounts::attach(&pool, &keys(), mine, &theirs)
        .await
        .unwrap();

    assert_eq!(added, Attach::OwnedElsewhere);
    assert_eq!(signed(&pool, &theirs).await, their_account);
}

#[tokio::test]
async fn a_verified_email_takes_the_address_back_from_an_unverified_claim() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let email = fresh_email();
    let squatter = signed(&pool, &claimed_email(Provider::Line, &email, false)).await;
    let real_owner = identity(&fresh_subject(), &email);

    let first_try = sign_in(&pool, &keys(), &real_owner).await.unwrap();
    let own_account = accounts::create_separate(&pool, &keys(), &real_owner)
        .await
        .unwrap();
    let later_claim = sign_in(
        &pool,
        &keys(),
        &claimed_email(Provider::Line, &email, false),
    )
    .await
    .unwrap();

    assert_eq!(first_try, SignIn::EmailTaken { holder: squatter });
    assert_ne!(own_account, squatter);
    assert_eq!(signed(&pool, &real_owner).await, own_account);
    assert_eq!(
        later_claim,
        SignIn::EmailTaken {
            holder: own_account
        }
    );
}

#[tokio::test]
async fn an_unverified_separate_account_never_takes_a_verified_email() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let email = fresh_email();
    let owner = signed(&pool, &identity(&fresh_subject(), &email)).await;
    let other = claimed_email(Provider::Line, &email, false);

    let separate = accounts::create_separate(&pool, &keys(), &other)
        .await
        .unwrap();
    let next_newcomer = sign_in(
        &pool,
        &keys(),
        &claimed_email(Provider::Line, &email, false),
    )
    .await
    .unwrap();

    assert_ne!(separate, owner);
    assert_eq!(signed(&pool, &other).await, separate);
    assert_eq!(next_newcomer, SignIn::EmailTaken { holder: owner });
}
