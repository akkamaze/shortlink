use anyhow::Context;
use deadpool_postgres::{Pool, Transaction};
use uuid::Uuid;

use super::provider::Provider;
use crate::crypto::{DataKeys, Field};

/// What a provider vouched for after its ID token passed verification.
pub struct VerifiedIdentity {
    pub provider: Provider,
    pub subject: String,
    pub email: String,
    pub display_name: Option<String>,
}

/// Finds or creates the user behind an identity and makes sure they own a
/// personal space. The database only ever sees the identity's keyed hash and
/// sealed copies of the email and name.
pub async fn sign_in(
    db: &Pool,
    keys: &DataKeys,
    identity: &VerifiedIdentity,
) -> anyhow::Result<Uuid> {
    let lookup = keys.lookup_hash(identity.provider.slug(), &identity.subject);

    let mut client = db.get().await.context("no database connection")?;
    let tx = client
        .transaction()
        .await
        .context("cannot start a transaction")?;

    let user_id = match existing_user(&tx, &lookup).await? {
        Some(user_id) => {
            store_profile(&tx, keys, user_id, identity).await?;
            user_id
        }
        None => create_user(&tx, keys, &lookup, identity).await?,
    };

    tx.execute(
        "INSERT INTO spaces (owner_user_id) VALUES ($1) ON CONFLICT (owner_user_id) DO NOTHING",
        &[&user_id],
    )
    .await
    .context("cannot create the personal space")?;

    tx.commit().await.context("cannot commit the sign-in")?;
    Ok(user_id)
}

async fn existing_user(tx: &Transaction<'_>, lookup: &[u8]) -> anyhow::Result<Option<Uuid>> {
    let row = tx
        .query_opt(
            "SELECT user_id FROM identities WHERE lookup_hash = $1",
            &[&lookup],
        )
        .await
        .context("cannot look up the identity")?;

    Ok(row.map(|row| row.get(0)))
}

async fn store_profile(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    user_id: Uuid,
    identity: &VerifiedIdentity,
) -> anyhow::Result<()> {
    let (email, display_name) = sealed_profile(keys, user_id, identity);

    tx.execute(
        "UPDATE users SET email_sealed = $2, display_name_sealed = $3 WHERE id = $1",
        &[&user_id, &email, &display_name],
    )
    .await
    .context("cannot refresh the user")?;

    Ok(())
}

/// Two first sign-ins for the same identity can race. The identity's primary
/// key picks the winner; the loser drops the user row it just made.
async fn create_user(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    lookup: &[u8],
    identity: &VerifiedIdentity,
) -> anyhow::Result<Uuid> {
    let new_user = Uuid::new_v4();
    let (email, display_name) = sealed_profile(keys, new_user, identity);

    tx.execute(
        "INSERT INTO users (id, email_sealed, display_name_sealed) VALUES ($1, $2, $3)",
        &[&new_user, &email, &display_name],
    )
    .await
    .context("cannot create the user")?;

    let inserted = tx
        .execute(
            "INSERT INTO identities (lookup_hash, provider, user_id) VALUES ($1, $2, $3)
             ON CONFLICT (lookup_hash) DO NOTHING",
            &[&lookup, &identity.provider.slug(), &new_user],
        )
        .await
        .context("cannot link the identity")?;

    let owner = if inserted == 1 {
        new_user
    } else {
        existing_user(tx, lookup)
            .await?
            .context("identity vanished after a conflicting insert")?
    };

    if owner != new_user {
        tx.execute("DELETE FROM users WHERE id = $1", &[&new_user])
            .await
            .context("cannot drop the duplicate user")?;
        store_profile(tx, keys, owner, identity).await?;
    }

    Ok(owner)
}

fn sealed_profile(
    keys: &DataKeys,
    user_id: Uuid,
    identity: &VerifiedIdentity,
) -> (Vec<u8>, Option<Vec<u8>>) {
    let email = keys.seal(&identity.email, Field::UserEmail, user_id);
    let display_name = identity
        .display_name
        .as_deref()
        .map(|name| keys.seal(name, Field::UserDisplayName, user_id));

    (email, display_name)
}
