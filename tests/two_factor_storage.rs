//! Runs against a real Postgres, like `auth_storage`: set `TEST_DATABASE_URL`
//! and `TEST_MIGRATION_DATABASE_URL`.

use axum_extra::extract::cookie::CookieJar;
use shortlink::{
    auth::{
        accounts::{VerifiedIdentity, sign_in},
        provider::Provider,
    },
    crypto::DataKeys,
    db,
    two_factor::{
        base32,
        store::{self, Check, Confirm, Status},
        totp, trusted,
    },
};
use uuid::Uuid;

static MIGRATED: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

/// A fixed moment, so codes do not depend on the wall clock.
const NOW: u64 = 1_900_000_000;

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

async fn new_user(pool: &deadpool_postgres::Pool) -> Uuid {
    let identity = VerifiedIdentity {
        provider: Provider::Google,
        subject: Uuid::new_v4().to_string(),
        email: None,
        display_name: None,
        picture: None,
    };
    sign_in(pool, &keys(), &identity).await.unwrap()
}

async fn code_at(pool: &deadpool_postgres::Pool, user: Uuid, unix: u64) -> String {
    let secret = store::setup_secret(pool, &keys(), user)
        .await
        .unwrap()
        .expect("setup in progress");
    let secret = base32::decode(&secret).unwrap();
    format!("{:06}", totp::code_at(&secret, totp::step_at(unix)))
}

/// Starts setup and confirms it; returns the recovery codes and the secret's
/// code for a later step.
async fn turned_on(pool: &deadpool_postgres::Pool, user: Uuid) -> (Vec<String>, String) {
    store::begin_setup(pool, &keys(), user).await.unwrap();
    let first = code_at(pool, user, NOW).await;
    let later = code_at(pool, user, NOW + 60).await;

    let Confirm::Enabled(codes) = store::confirm(pool, &keys(), user, &first, NOW)
        .await
        .unwrap()
    else {
        panic!("setup should confirm");
    };
    (codes, later)
}

#[tokio::test]
async fn setup_turns_on_only_after_a_right_code() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;

    let before = store::status(&pool, user).await.unwrap();
    store::begin_setup(&pool, &keys(), user).await.unwrap();
    let during = store::status(&pool, user).await.unwrap();
    let right = code_at(&pool, user, NOW).await;
    let wrong = if right == "000000" {
        "111111"
    } else {
        "000000"
    };

    let refused = store::confirm(&pool, &keys(), user, wrong, NOW)
        .await
        .unwrap();
    let confirmed = store::confirm(&pool, &keys(), user, &right, NOW)
        .await
        .unwrap();

    assert_eq!(before, Status::Off);
    assert_eq!(during, Status::SettingUp);
    assert_eq!(refused, Confirm::WrongCode);
    assert!(matches!(&confirmed, Confirm::Enabled(codes) if codes.len() == 10));
    assert_eq!(store::status(&pool, user).await.unwrap(), Status::On);
}

#[tokio::test]
async fn each_app_code_works_once() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    let (_, later) = turned_on(&pool, user).await;

    let first = store::verify(&pool, &keys(), user, &later, NOW + 60)
        .await
        .unwrap();
    let replay = store::verify(&pool, &keys(), user, &later, NOW + 60)
        .await
        .unwrap();

    assert_eq!(first, Check::Passed);
    assert_eq!(replay, Check::WrongCode);
}

#[tokio::test]
async fn each_recovery_code_works_once_in_any_case() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    let (codes, _) = turned_on(&pool, user).await;
    let typed = codes[3].to_lowercase().replace('-', " ");

    let first = store::verify(&pool, &keys(), user, &typed, NOW + 60)
        .await
        .unwrap();
    let again = store::verify(&pool, &keys(), user, &codes[3], NOW + 60)
        .await
        .unwrap();
    let another = store::verify(&pool, &keys(), user, &codes[4], NOW + 60)
        .await
        .unwrap();

    assert_eq!(
        (first, again, another),
        (Check::Passed, Check::WrongCode, Check::Passed)
    );
}

#[tokio::test]
async fn five_wrong_codes_lock_out_even_the_right_one() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    let (_, later) = turned_on(&pool, user).await;

    let mut outcomes = Vec::new();
    for _ in 0..5 {
        outcomes.push(
            store::verify(&pool, &keys(), user, "WRONG-CODE", NOW + 60)
                .await
                .unwrap(),
        );
    }
    let right_but_locked = store::verify(&pool, &keys(), user, &later, NOW + 60)
        .await
        .unwrap();

    assert_eq!(
        outcomes[..4],
        [
            Check::WrongCode,
            Check::WrongCode,
            Check::WrongCode,
            Check::WrongCode
        ]
    );
    assert_eq!(outcomes[4], Check::Locked);
    assert_eq!(right_but_locked, Check::Locked);
}

#[tokio::test]
async fn a_right_code_resets_the_wrong_code_count() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    let (codes, _) = turned_on(&pool, user).await;

    for _ in 0..4 {
        store::verify(&pool, &keys(), user, "WRONG-CODE", NOW)
            .await
            .unwrap();
    }
    store::verify(&pool, &keys(), user, &codes[0], NOW)
        .await
        .unwrap();
    let after_reset = store::verify(&pool, &keys(), user, "WRONG-CODE", NOW)
        .await
        .unwrap();

    assert_eq!(after_reset, Check::WrongCode);
}

#[tokio::test]
async fn setup_cannot_replace_a_secret_that_is_on() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    let (_, later) = turned_on(&pool, user).await;

    store::begin_setup(&pool, &keys(), user).await.unwrap();
    let still_works = store::verify(&pool, &keys(), user, &later, NOW + 60)
        .await
        .unwrap();

    assert_eq!(store::status(&pool, user).await.unwrap(), Status::On);
    assert_eq!(still_works, Check::Passed);
}

#[tokio::test]
async fn turning_off_forgets_the_secret_and_codes() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    let (codes, _) = turned_on(&pool, user).await;

    store::turn_off(&pool, user).await.unwrap();
    let recovery_after = store::verify(&pool, &keys(), user, &codes[0], NOW)
        .await
        .unwrap();

    assert_eq!(store::status(&pool, user).await.unwrap(), Status::Off);
    assert_eq!(recovery_after, Check::WrongCode);
}

#[tokio::test]
async fn the_database_holds_no_readable_secret_or_recovery_code() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    store::begin_setup(&pool, &keys(), user).await.unwrap();
    let secret = store::setup_secret(&pool, &keys(), user)
        .await
        .unwrap()
        .unwrap();
    let first = code_at(&pool, user, NOW).await;
    let Confirm::Enabled(codes) = store::confirm(&pool, &keys(), user, &first, NOW)
        .await
        .unwrap()
    else {
        panic!("setup should confirm");
    };

    let client = pool.get().await.unwrap();
    let mut dump = String::new();
    for table in ["totp_factors", "recovery_codes"] {
        for row in client
            .query(
                &format!("SELECT row_to_json(t)::text FROM {table} t WHERE user_id = $1"),
                &[&user],
            )
            .await
            .unwrap()
        {
            dump.push_str(row.get::<_, &str>(0));
        }
    }

    assert!(!dump.contains(&secret), "the base32 secret is readable");
    for code in &codes {
        assert!(!dump.contains(&code.replace('-', "")), "{code} is readable");
    }
}

fn jar_with(token: trusted::TrustToken) -> CookieJar {
    CookieJar::new().add(token.into_cookie(false))
}

#[tokio::test]
async fn a_trusted_browser_counts_only_for_its_user_until_forgotten() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    let someone_else = new_user(&pool).await;
    let jar = jar_with(trusted::trust(&pool, user).await.unwrap());

    let for_user = trusted::is_trusted(&pool, &jar, user).await.unwrap();
    let for_someone_else = trusted::is_trusted(&pool, &jar, someone_else)
        .await
        .unwrap();
    let without_cookie = trusted::is_trusted(&pool, &CookieJar::new(), user)
        .await
        .unwrap();
    trusted::forget_all(&pool, user).await.unwrap();
    let after_forgetting = trusted::is_trusted(&pool, &jar, user).await.unwrap();

    assert!(for_user);
    assert!(!for_someone_else);
    assert!(!without_cookie);
    assert!(!after_forgetting);
}

#[tokio::test]
async fn turning_two_factor_off_forgets_trusted_browsers() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    turned_on(&pool, user).await;
    let jar = jar_with(trusted::trust(&pool, user).await.unwrap());

    store::turn_off(&pool, user).await.unwrap();

    assert!(!trusted::is_trusted(&pool, &jar, user).await.unwrap());
}

#[tokio::test]
async fn an_expired_trust_counts_for_nothing_and_is_cleaned_up() {
    let Some(pool) = test_pool().await else {
        return;
    };
    let user = new_user(&pool).await;
    let jar = jar_with(trusted::trust(&pool, user).await.unwrap());
    let fresh = trusted::is_trusted(&pool, &jar, user).await.unwrap();

    // The app role may not change expiry; the owner role stands in for time passing.
    let owner = db::connect_pool(&std::env::var("TEST_MIGRATION_DATABASE_URL").unwrap()).unwrap();
    owner
        .get()
        .await
        .unwrap()
        .execute(
            "UPDATE trusted_devices
             SET created_at = now() - interval '31 days', expires_at = now() - interval '1 day'
             WHERE user_id = $1",
            &[&user],
        )
        .await
        .unwrap();

    let expired = trusted::is_trusted(&pool, &jar, user).await.unwrap();
    trusted::delete_expired(&pool).await.unwrap();
    let left: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM trusted_devices WHERE user_id = $1",
            &[&user],
        )
        .await
        .unwrap()
        .get(0);

    assert!(fresh);
    assert!(!expired);
    assert_eq!(left, 0);
}
