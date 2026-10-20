use anyhow::Context;
use deadpool_postgres::{Pool, Transaction};
use uuid::Uuid;

use super::{base32, recovery, totp};
use crate::crypto::{DataKeys, Field};

/// Wrong codes in a row before the account stops taking codes for a while.
const MAX_FAILED_ATTEMPTS: i32 = 5;
const LOCK_MINUTES: i32 = 15;

const RECOVERY_NAMESPACE: &str = "recovery-code";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Off,
    /// A secret was shown but no code has been typed yet.
    SettingUp,
    On,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Check {
    Passed,
    WrongCode,
    Locked,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Confirm {
    /// Two-factor is on; these recovery codes are shown once.
    Enabled(Vec<String>),
    WrongCode,
    Locked,
    NotSettingUp,
}

pub async fn status(db: &Pool, user_id: Uuid) -> anyhow::Result<Status> {
    let client = db.get().await.context("no database connection")?;
    let row = client
        .query_opt(
            "SELECT confirmed_at IS NOT NULL FROM totp_factors WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .context("cannot read the two-factor status")?;

    Ok(match row.map(|row| row.get::<_, bool>(0)) {
        None => Status::Off,
        Some(false) => Status::SettingUp,
        Some(true) => Status::On,
    })
}

/// Starts or restarts setup with a fresh secret. An account that already has
/// two-factor on keeps its secret; it must turn it off first.
pub async fn begin_setup(db: &Pool, keys: &DataKeys, user_id: Uuid) -> anyhow::Result<()> {
    let mut secret = [0u8; totp::SECRET_LEN];
    rand::fill(&mut secret);
    let sealed = keys.seal(&base32::encode(&secret), Field::TotpSecret, user_id);

    let client = db.get().await.context("no database connection")?;
    client
        .execute(
            "INSERT INTO totp_factors (user_id, secret_sealed) VALUES ($1, $2)
             ON CONFLICT (user_id) DO UPDATE
                 SET secret_sealed = EXCLUDED.secret_sealed, failed_attempts = 0,
                     locked_until = NULL, last_used_step = NULL, created_at = now()
                 WHERE totp_factors.confirmed_at IS NULL",
            &[&user_id, &sealed],
        )
        .await
        .context("cannot start two-factor setup")?;

    Ok(())
}

/// The base32 secret while setup is in progress, for the QR code.
pub async fn setup_secret(
    db: &Pool,
    keys: &DataKeys,
    user_id: Uuid,
) -> anyhow::Result<Option<String>> {
    let client = db.get().await.context("no database connection")?;
    let row = client
        .query_opt(
            "SELECT secret_sealed FROM totp_factors
             WHERE user_id = $1 AND confirmed_at IS NULL",
            &[&user_id],
        )
        .await
        .context("cannot read the setup secret")?;

    row.map(|row| {
        keys.open(row.get(0), Field::TotpSecret, user_id)
            .context("the setup secret cannot be opened")
    })
    .transpose()
}

/// Turns two-factor on once the first code from the app is right.
pub async fn confirm(
    db: &Pool,
    keys: &DataKeys,
    user_id: Uuid,
    typed: &str,
    now_unix: u64,
) -> anyhow::Result<Confirm> {
    let mut client = db.get().await.context("no database connection")?;
    let tx = client
        .transaction()
        .await
        .context("cannot start a transaction")?;

    let Some(factor) = locked_factor(&tx, keys, user_id).await? else {
        return Ok(Confirm::NotSettingUp);
    };
    if factor.confirmed {
        return Ok(Confirm::NotSettingUp);
    }
    if factor.locked {
        return Ok(Confirm::Locked);
    }

    let Some(step) = totp::matching_step(&factor.secret, typed, totp::step_at(now_unix)) else {
        let outcome = record_failure(&tx, user_id).await?;
        tx.commit().await.context("cannot record the failed code")?;
        return Ok(match outcome {
            Check::Locked => Confirm::Locked,
            _ => Confirm::WrongCode,
        });
    };

    tx.execute(
        "UPDATE totp_factors
         SET confirmed_at = now(), last_used_step = $2, failed_attempts = 0
         WHERE user_id = $1",
        &[&user_id, &step_number(step)?],
    )
    .await
    .context("cannot turn two-factor on")?;
    let codes = replace_recovery_codes(&tx, keys, user_id).await?;

    tx.commit()
        .await
        .context("cannot commit two-factor setup")?;
    Ok(Confirm::Enabled(codes))
}

/// Checks a code from the app, or an unused recovery code, for an account
/// with two-factor on. Each code works once.
pub async fn verify(
    db: &Pool,
    keys: &DataKeys,
    user_id: Uuid,
    typed: &str,
    now_unix: u64,
) -> anyhow::Result<Check> {
    let mut client = db.get().await.context("no database connection")?;
    let tx = client
        .transaction()
        .await
        .context("cannot start a transaction")?;

    let Some(factor) = locked_factor(&tx, keys, user_id)
        .await?
        .filter(|factor| factor.confirmed)
    else {
        return Ok(Check::WrongCode);
    };
    if factor.locked {
        return Ok(Check::Locked);
    }

    let fresh_step = totp::matching_step(&factor.secret, typed, totp::step_at(now_unix))
        .filter(|step| factor.last_used_step.is_none_or(|last| *step > last));
    let passed = match fresh_step {
        Some(step) => {
            tx.execute(
                "UPDATE totp_factors SET last_used_step = $2 WHERE user_id = $1",
                &[&user_id, &step_number(step)?],
            )
            .await
            .context("cannot record the used code")?;
            true
        }
        None => use_recovery_code(&tx, keys, user_id, typed).await?,
    };

    let outcome = if passed {
        tx.execute(
            "UPDATE totp_factors SET failed_attempts = 0 WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .context("cannot reset the wrong-code count")?;
        Check::Passed
    } else {
        record_failure(&tx, user_id).await?
    };
    tx.commit().await.context("cannot commit the code check")?;
    Ok(outcome)
}

pub async fn turn_off(db: &Pool, user_id: Uuid) -> anyhow::Result<()> {
    let mut client = db.get().await.context("no database connection")?;
    let tx = client
        .transaction()
        .await
        .context("cannot start a transaction")?;

    tx.execute("DELETE FROM recovery_codes WHERE user_id = $1", &[&user_id])
        .await
        .context("cannot delete the recovery codes")?;
    tx.execute("DELETE FROM totp_factors WHERE user_id = $1", &[&user_id])
        .await
        .context("cannot turn two-factor off")?;

    tx.commit()
        .await
        .context("cannot commit turning two-factor off")?;
    Ok(())
}

struct Factor {
    secret: Vec<u8>,
    confirmed: bool,
    locked: bool,
    last_used_step: Option<u64>,
}

/// Reads the factor and holds its row, so two codes typed at once are
/// counted and used one after the other.
async fn locked_factor(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    user_id: Uuid,
) -> anyhow::Result<Option<Factor>> {
    let Some(row) = tx
        .query_opt(
            "SELECT secret_sealed, confirmed_at IS NOT NULL,
                    coalesce(locked_until > now(), false), last_used_step
             FROM totp_factors WHERE user_id = $1 FOR UPDATE",
            &[&user_id],
        )
        .await
        .context("cannot read the two-factor secret")?
    else {
        return Ok(None);
    };

    let secret = keys
        .open(row.get(0), Field::TotpSecret, user_id)
        .context("the two-factor secret cannot be opened")?;
    let last_used_step: Option<i64> = row.get(3);

    Ok(Some(Factor {
        secret: base32::decode(&secret).context("the stored secret is not base32")?,
        confirmed: row.get(1),
        locked: row.get(2),
        last_used_step: last_used_step.and_then(|step| u64::try_from(step).ok()),
    }))
}

/// Counts a wrong code. The fifth in a row locks the account's codes for
/// fifteen minutes and starts the count again.
async fn record_failure(tx: &Transaction<'_>, user_id: Uuid) -> anyhow::Result<Check> {
    let locked: bool = tx
        .query_one(
            "UPDATE totp_factors
             SET failed_attempts = CASE WHEN failed_attempts + 1 >= $2 THEN 0
                                        ELSE failed_attempts + 1 END,
                 locked_until = CASE WHEN failed_attempts + 1 >= $2
                                     THEN now() + make_interval(mins => $3)
                                     ELSE locked_until END
             WHERE user_id = $1
             RETURNING coalesce(locked_until > now(), false)",
            &[&user_id, &MAX_FAILED_ATTEMPTS, &LOCK_MINUTES],
        )
        .await
        .context("cannot count the wrong code")?
        .get(0);

    Ok(if locked {
        Check::Locked
    } else {
        Check::WrongCode
    })
}

async fn use_recovery_code(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    user_id: Uuid,
    typed: &str,
) -> anyhow::Result<bool> {
    let hash = keys.lookup_hash(RECOVERY_NAMESPACE, &recovery::normalize(typed));

    let used = tx
        .execute(
            "UPDATE recovery_codes SET used_at = now()
             WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL",
            &[&user_id, &hash],
        )
        .await
        .context("cannot use the recovery code")?;

    Ok(used == 1)
}

async fn replace_recovery_codes(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    user_id: Uuid,
) -> anyhow::Result<Vec<String>> {
    tx.execute("DELETE FROM recovery_codes WHERE user_id = $1", &[&user_id])
        .await
        .context("cannot clear the old recovery codes")?;

    let codes = recovery::generate();
    for code in &codes {
        let hash = keys.lookup_hash(RECOVERY_NAMESPACE, &recovery::normalize(code));
        tx.execute(
            "INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)",
            &[&user_id, &hash],
        )
        .await
        .context("cannot store a recovery code")?;
    }

    Ok(codes)
}

fn step_number(step: u64) -> anyhow::Result<i64> {
    i64::try_from(step).context("the time step does not fit the database column")
}
