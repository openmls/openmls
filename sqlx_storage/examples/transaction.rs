//! Using the SQLx storage provider inside a SQLite transaction.
//!
//! The [`SqliteStorageProvider`] borrows a [`SqliteConnection`]. A
//! [`sqlx::Transaction`] dereferences to a [`SqliteConnection`], so the same
//! provider can run against an open transaction by passing `&mut *transaction`.
//! Every write the provider performs then becomes part of that transaction and
//! either commits or rolls back together with the rest of your application's
//! writes.
//!
//! This example walks through two scenarios:
//!
//! 1. A transaction that writes OpenMLS state alongside an application row and
//!    commits both atomically.
//! 2. A transaction that writes the same kind of data but rolls back, leaving
//!    the database untouched.
//!
//! Run it with `cargo run --example transaction`.

use openmls_sqlx_storage::{Codec, SqliteStorageProvider};
use openmls_traits::storage::{CURRENT_VERSION, Entity, Key, StorageProvider, traits};
use serde::{Deserialize, Serialize};
use sqlx::{Connection, Row, SqliteConnection, Transaction, sqlite::Sqlite};

/// A codec backed by `serde_json`. The provider is generic over the codec used
/// to serialize and deserialize stored values.
#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// A signature public key, used here as the lookup key for a key pair.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct SignaturePublicKey(Vec<u8>);
impl Key<CURRENT_VERSION> for SignaturePublicKey {}
impl traits::SignaturePublicKey<CURRENT_VERSION> for SignaturePublicKey {}

/// A signature key pair, the value stored under a [`SignaturePublicKey`].
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct SignatureKeyPair(Vec<u8>);
impl Entity<CURRENT_VERSION> for SignatureKeyPair {}
impl traits::SignatureKeyPair<CURRENT_VERSION> for SignatureKeyPair {}

// The provider performs blocking calls internally, so it needs a multi-threaded
// runtime.
#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = SqliteConnection::connect("sqlite::memory:").await?;

    // Run the provider's migrations once, on the bare connection, before any
    // transactions. Migrations create their own tables and should not be tied
    // to the lifetime of a single transaction.
    SqliteStorageProvider::<JsonCodec>::new(&mut connection).run_migrations()?;

    // An application-owned table that lives next to the OpenMLS tables in the
    // same database.
    sqlx::query("CREATE TABLE accounts (name TEXT PRIMARY KEY, key BLOB NOT NULL)")
        .execute(&mut connection)
        .await?;

    let public_key = SignaturePublicKey(b"public-key".to_vec());
    let key_pair = SignatureKeyPair(b"key-pair".to_vec());

    commit_scenario(&mut connection, &public_key, &key_pair).await?;
    rollback_scenario(&mut connection, &public_key).await?;

    Ok(())
}

/// Write OpenMLS state and an application row in one transaction, then commit.
async fn commit_scenario(
    connection: &mut SqliteConnection,
    public_key: &SignaturePublicKey,
    key_pair: &SignatureKeyPair,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut transaction = connection.begin().await?;

    // The provider borrows the transaction for as long as it is alive, so we
    // scope it. Once it is dropped, the transaction is free to be used directly
    // again and to be committed.
    {
        let storage = SqliteStorageProvider::<JsonCodec>::new(&mut transaction);
        storage.write_signature_key_pair(public_key, key_pair)?;
    }

    // The same transaction also carries an application write.
    sqlx::query("INSERT INTO accounts (name, key) VALUES (?, ?)")
        .bind("alice")
        .bind(&public_key.0)
        .execute(&mut *transaction)
        .await?;

    transaction.commit().await?;

    let stored: Option<SignatureKeyPair> = read_key_pair(connection, public_key).await?;
    let account_count = count_accounts(connection).await?;
    println!("after commit: key pair stored = {}", stored.is_some());
    println!("after commit: account rows = {account_count}");
    assert_eq!(stored.as_ref(), Some(key_pair));
    assert_eq!(account_count, 1);

    Ok(())
}

/// Write the same kind of data, then roll back. Neither write survives.
async fn rollback_scenario(
    connection: &mut SqliteConnection,
    public_key: &SignaturePublicKey,
) -> Result<(), Box<dyn std::error::Error>> {
    let discarded_key = SignaturePublicKey(b"discarded".to_vec());
    let discarded_pair = SignatureKeyPair(b"discarded".to_vec());

    let mut transaction = connection.begin().await?;
    {
        let storage = SqliteStorageProvider::<JsonCodec>::new(&mut transaction);
        storage.write_signature_key_pair(&discarded_key, &discarded_pair)?;
    }
    sqlx::query("INSERT INTO accounts (name, key) VALUES (?, ?)")
        .bind("bob")
        .bind(&discarded_key.0)
        .execute(&mut *transaction)
        .await?;

    transaction.rollback().await?;

    let discarded: Option<SignatureKeyPair> = read_key_pair(connection, &discarded_key).await?;
    let account_count = count_accounts(connection).await?;
    println!(
        "after rollback: discarded key pair stored = {}",
        discarded.is_some()
    );
    println!("after rollback: account rows = {account_count}");
    assert!(discarded.is_none());
    // Only the row from the committed scenario remains.
    assert_eq!(account_count, 1);

    // The key pair from the committed scenario is still present.
    let survivor: Option<SignatureKeyPair> = read_key_pair(connection, public_key).await?;
    assert!(survivor.is_some());

    Ok(())
}

/// Read a key pair through a short-lived provider over a transaction.
async fn read_key_pair(
    connection: &mut SqliteConnection,
    public_key: &SignaturePublicKey,
) -> Result<Option<SignatureKeyPair>, Box<dyn std::error::Error>> {
    let mut transaction: Transaction<'_, Sqlite> = connection.begin().await?;
    let stored = {
        let storage = SqliteStorageProvider::<JsonCodec>::new(&mut transaction);
        storage.signature_key_pair(public_key)?
    };
    transaction.commit().await?;
    Ok(stored)
}

/// Count the rows in the application-owned `accounts` table.
async fn count_accounts(
    connection: &mut SqliteConnection,
) -> Result<i64, Box<dyn std::error::Error>> {
    let row = sqlx::query("SELECT COUNT(*) AS count FROM accounts")
        .fetch_one(connection)
        .await?;
    Ok(row.get::<i64, _>("count"))
}
