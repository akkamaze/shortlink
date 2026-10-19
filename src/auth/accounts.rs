use anyhow::Context;
use deadpool_postgres::{Pool, Transaction};
use uuid::Uuid;

use super::{picture::PictureUrl, provider::Provider};
use crate::crypto::{DataKeys, Field};

/// What a provider vouched for after its ID token or profile passed checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub provider: Provider,
    pub subject: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub picture: Option<PictureUrl>,
}

/// Finds or creates the user behind an identity and makes sure they own a
/// personal space. Each identity is its own account: a Google and a
/// Facebook sign-in with the same email stay apart. The database only ever
/// sees the identity's keyed hash and sealed copies of the email, name and
/// picture.
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

    let user_id = match identity_owner(&tx, &lookup).await? {
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

async fn identity_owner(tx: &Transaction<'_>, lookup: &[u8]) -> anyhow::Result<Option<Uuid>> {
    let row = tx
        .query_opt(
            "SELECT user_id FROM identities WHERE lookup_hash = $1",
            &[&lookup],
        )
        .await
        .context("cannot look up the identity")?;

    Ok(row.map(|row| row.get(0)))
}

/// Each sign-in replaces the profile with what the provider sends now, so a
/// name or picture removed there disappears here too.
async fn store_profile(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    user_id: Uuid,
    identity: &VerifiedIdentity,
) -> anyhow::Result<()> {
    let profile = sealed_profile(keys, user_id, identity);

    tx.execute(
        "UPDATE users
         SET email_sealed = $2, display_name_sealed = $3, picture_sealed = $4
         WHERE id = $1",
        &[
            &user_id,
            &profile.email,
            &profile.display_name,
            &profile.picture,
        ],
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
    let profile = sealed_profile(keys, new_user, identity);

    tx.execute(
        "INSERT INTO users (id, email_sealed, display_name_sealed, picture_sealed)
         VALUES ($1, $2, $3, $4)",
        &[
            &new_user,
            &profile.email,
            &profile.display_name,
            &profile.picture,
        ],
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
        .context("cannot record the identity")?;
    if inserted == 1 {
        return Ok(new_user);
    }

    let owner = identity_owner(tx, lookup)
        .await?
        .context("identity vanished after a conflicting insert")?;
    tx.execute("DELETE FROM users WHERE id = $1", &[&new_user])
        .await
        .context("cannot drop the duplicate user")?;
    store_profile(tx, keys, owner, identity).await?;

    Ok(owner)
}

struct SealedProfile {
    email: Option<Vec<u8>>,
    display_name: Option<Vec<u8>>,
    picture: Option<Vec<u8>>,
}

fn sealed_profile(keys: &DataKeys, user_id: Uuid, identity: &VerifiedIdentity) -> SealedProfile {
    let seal = |value: Option<&str>, field| value.map(|value| keys.seal(value, field, user_id));

    SealedProfile {
        email: seal(identity.email.as_deref(), Field::UserEmail),
        display_name: seal(identity.display_name.as_deref(), Field::UserDisplayName),
        picture: seal(
            identity.picture.as_ref().map(PictureUrl::as_str),
            Field::UserPicture,
        ),
    }
}
