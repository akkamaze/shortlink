use anyhow::Context;
use deadpool_postgres::{Pool, Transaction};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{picture::PictureUrl, provider::Provider};
use crate::crypto::{DataKeys, Field};

/// What a provider vouched for after its ID token or profile passed checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedIdentity {
    pub provider: Provider,
    pub subject: String,
    pub email: Option<ProviderEmail>,
    pub display_name: Option<String>,
    pub picture: Option<PictureUrl>,
}

/// An email as the provider gave it. `verified` is true only when the
/// provider says it confirmed the address (Google's `email_verified`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEmail {
    pub address: String,
    pub verified: bool,
}

/// How a sign-in ended. An unknown identity whose email already belongs to
/// an account is never joined to it here: the owner must confirm first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignIn {
    Signed(Uuid),
    EmailTaken { holder: Uuid },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attach {
    Attached,
    OwnedElsewhere,
}

const EMAIL_NAMESPACE: &str = "user-email";

/// `" Ann@Example.com "` and `"ann@example.com"` give the same hash.
pub fn email_lookup(keys: &DataKeys, address: &str) -> Vec<u8> {
    keys.lookup_hash(EMAIL_NAMESPACE, &address.trim().to_lowercase())
}

/// Finds or creates the user behind an identity and makes sure they own a
/// personal space. The database only ever sees keyed hashes and sealed
/// copies of the email, name and picture.
pub async fn sign_in(
    db: &Pool,
    keys: &DataKeys,
    identity: &VerifiedIdentity,
) -> anyhow::Result<SignIn> {
    let lookup = identity_lookup(keys, identity);

    let mut client = db.get().await.context("no database connection")?;
    let tx = client
        .transaction()
        .await
        .context("cannot start a transaction")?;

    let outcome = match identity_owner(&tx, &lookup).await? {
        Some(user_id) => {
            store_profile(&tx, keys, user_id, identity).await?;
            SignIn::Signed(user_id)
        }
        None => match email_holder(&tx, keys, identity).await? {
            Some(holder) => SignIn::EmailTaken { holder },
            None => create_user(&tx, keys, &lookup, identity, EmailClaim::Claim).await?,
        },
    };

    if let SignIn::Signed(user_id) = outcome {
        ensure_space(&tx, user_id).await?;
    }

    tx.commit().await.context("cannot commit the sign-in")?;
    Ok(outcome)
}

/// Adds an identity to an account its owner has just signed in to. The
/// account keeps its own profile.
pub async fn attach(
    db: &Pool,
    keys: &DataKeys,
    user_id: Uuid,
    identity: &VerifiedIdentity,
) -> anyhow::Result<Attach> {
    let lookup = identity_lookup(keys, identity);
    let client = db.get().await.context("no database connection")?;

    client
        .execute(
            "INSERT INTO identities (lookup_hash, provider, user_id) VALUES ($1, $2, $3)
             ON CONFLICT (lookup_hash) DO NOTHING",
            &[&lookup, &identity.provider.slug(), &user_id],
        )
        .await
        .context("cannot attach the identity")?;

    let owner = client
        .query_one(
            "SELECT user_id FROM identities WHERE lookup_hash = $1",
            &[&lookup],
        )
        .await
        .context("cannot read the identity back")?
        .get::<_, Uuid>(0);

    Ok(if owner == user_id {
        Attach::Attached
    } else {
        Attach::OwnedElsewhere
    })
}

/// Creates a new account for an identity whose email another account holds.
/// A verified email takes the address over from an account that only
/// claimed it unverified; otherwise the new account goes without one.
pub async fn create_separate(
    db: &Pool,
    keys: &DataKeys,
    identity: &VerifiedIdentity,
) -> anyhow::Result<Uuid> {
    let lookup = identity_lookup(keys, identity);

    let mut client = db.get().await.context("no database connection")?;
    let tx = client
        .transaction()
        .await
        .context("cannot start a transaction")?;

    if let Some(user_id) = identity_owner(&tx, &lookup).await? {
        return Ok(user_id);
    }

    if let Some(email) = identity.email.as_ref().filter(|email| email.verified) {
        tx.execute(
            "UPDATE users SET email_lookup = NULL
             WHERE email_lookup = $1 AND NOT email_verified",
            &[&email_lookup(keys, &email.address)],
        )
        .await
        .context("cannot release an unverified email")?;
    }
    let claim = match email_holder(&tx, keys, identity).await? {
        Some(_) => EmailClaim::Skip,
        None => EmailClaim::Claim,
    };

    let SignIn::Signed(user_id) = create_user(&tx, keys, &lookup, identity, claim).await? else {
        anyhow::bail!("another sign-in took the email at the same moment; try again");
    };
    ensure_space(&tx, user_id).await?;

    tx.commit()
        .await
        .context("cannot commit the separate account")?;
    Ok(user_id)
}

/// Providers that open an account, in button order.
pub async fn sign_in_providers(db: &Pool, user_id: Uuid) -> anyhow::Result<Vec<Provider>> {
    let client = db.get().await.context("no database connection")?;
    let rows = client
        .query(
            "SELECT provider FROM identities WHERE user_id = $1",
            &[&user_id],
        )
        .await
        .context("cannot list the account's sign-ins")?;

    let linked: Vec<&str> = rows.iter().map(|row| row.get(0)).collect();
    Ok(Provider::ALL
        .into_iter()
        .filter(|provider| linked.contains(&provider.slug()))
        .collect())
}

fn identity_lookup(keys: &DataKeys, identity: &VerifiedIdentity) -> Vec<u8> {
    keys.lookup_hash(identity.provider.slug(), &identity.subject)
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

async fn email_holder(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    identity: &VerifiedIdentity,
) -> anyhow::Result<Option<Uuid>> {
    let Some(email) = &identity.email else {
        return Ok(None);
    };

    let row = tx
        .query_opt(
            "SELECT id FROM users WHERE email_lookup = $1",
            &[&email_lookup(keys, &email.address)],
        )
        .await
        .context("cannot look up the email")?;

    Ok(row.map(|row| row.get(0)))
}

async fn ensure_space(tx: &Transaction<'_>, user_id: Uuid) -> anyhow::Result<()> {
    tx.execute(
        "INSERT INTO spaces (owner_user_id) VALUES ($1) ON CONFLICT (owner_user_id) DO NOTHING",
        &[&user_id],
    )
    .await
    .context("cannot create the personal space")?;

    Ok(())
}

/// Each sign-in replaces the profile with what the provider sends now, so a
/// name or picture removed there disappears here too. The email lookup
/// follows the new address unless another account already holds it.
async fn store_profile(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    user_id: Uuid,
    identity: &VerifiedIdentity,
) -> anyhow::Result<()> {
    let profile = sealed_profile(keys, user_id, identity);

    tx.execute(
        "UPDATE users
         SET email_sealed = $2, display_name_sealed = $3, picture_sealed = $4,
             email_verified = $6,
             email_lookup = CASE
                 WHEN $5::bytea IS NULL THEN NULL
                 WHEN EXISTS (SELECT 1 FROM users other
                              WHERE other.email_lookup = $5 AND other.id <> $1) THEN NULL
                 ELSE $5
             END
         WHERE id = $1",
        &[
            &user_id,
            &profile.email,
            &profile.display_name,
            &profile.picture,
            &profile.email_lookup,
            &profile.email_verified,
        ],
    )
    .await
    .context("cannot refresh the user")?;

    Ok(())
}

#[derive(Clone, Copy)]
enum EmailClaim {
    Claim,
    Skip,
}

/// Two first sign-ins can race. The identity's primary key and the email's
/// unique lookup pick the winner; the loser drops the user row it just made.
async fn create_user(
    tx: &Transaction<'_>,
    keys: &DataKeys,
    lookup: &[u8],
    identity: &VerifiedIdentity,
    claim: EmailClaim,
) -> anyhow::Result<SignIn> {
    let new_user = Uuid::new_v4();
    let profile = sealed_profile(keys, new_user, identity);
    let email_lookup = match claim {
        EmailClaim::Claim => profile.email_lookup.clone(),
        EmailClaim::Skip => None,
    };

    let created = tx
        .execute(
            "INSERT INTO users
                 (id, email_sealed, display_name_sealed, picture_sealed, email_lookup, email_verified)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (email_lookup) DO NOTHING",
            &[
                &new_user,
                &profile.email,
                &profile.display_name,
                &profile.picture,
                &email_lookup,
                &profile.email_verified,
            ],
        )
        .await
        .context("cannot create the user")?;
    if created == 0 {
        if let Some(owner) = identity_owner(tx, lookup).await? {
            store_profile(tx, keys, owner, identity).await?;
            return Ok(SignIn::Signed(owner));
        }
        let holder = email_holder(tx, keys, identity)
            .await?
            .context("email holder vanished after a conflicting insert")?;
        return Ok(SignIn::EmailTaken { holder });
    }

    let inserted = tx
        .execute(
            "INSERT INTO identities (lookup_hash, provider, user_id) VALUES ($1, $2, $3)
             ON CONFLICT (lookup_hash) DO NOTHING",
            &[&lookup, &identity.provider.slug(), &new_user],
        )
        .await
        .context("cannot record the identity")?;
    if inserted == 1 {
        return Ok(SignIn::Signed(new_user));
    }

    let owner = identity_owner(tx, lookup)
        .await?
        .context("identity vanished after a conflicting insert")?;
    tx.execute("DELETE FROM users WHERE id = $1", &[&new_user])
        .await
        .context("cannot drop the duplicate user")?;
    store_profile(tx, keys, owner, identity).await?;

    Ok(SignIn::Signed(owner))
}

struct SealedProfile {
    email: Option<Vec<u8>>,
    email_lookup: Option<Vec<u8>>,
    email_verified: bool,
    display_name: Option<Vec<u8>>,
    picture: Option<Vec<u8>>,
}

fn sealed_profile(keys: &DataKeys, user_id: Uuid, identity: &VerifiedIdentity) -> SealedProfile {
    let seal = |value: Option<&str>, field| value.map(|value| keys.seal(value, field, user_id));
    let address = identity.email.as_ref().map(|email| email.address.as_str());

    SealedProfile {
        email: seal(address, Field::UserEmail),
        email_lookup: address.map(|address| email_lookup(keys, address)),
        email_verified: identity.email.as_ref().is_some_and(|email| email.verified),
        display_name: seal(identity.display_name.as_deref(), Field::UserDisplayName),
        picture: seal(
            identity.picture.as_ref().map(PictureUrl::as_str),
            Field::UserPicture,
        ),
    }
}
