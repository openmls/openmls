# OpenMLS SQLite Storage

A codec-independent storage provider implementing the `StorageProvider` trait
from `openmls_traits` based on the `sqlx` crate.

Currently only the sqlite backend is supported.

## Usage

The provider borrows a `SqliteConnection`. Create one, run the migrations once,
then build a provider whenever you need to read or write OpenMLS state:

```rust,ignore
use openmls_sqlx_storage::SqliteStorageProvider;
use sqlx::{Connection, SqliteConnection};

let mut connection = SqliteConnection::connect("sqlite://storage.db").await?;
SqliteStorageProvider::<JsonCodec>::new(&mut connection).run_migrations()?;

let storage = SqliteStorageProvider::<JsonCodec>::new(&mut connection);
// pass `storage` to OpenMLS via a `Provider`
```

The provider is generic over a `Codec` that controls how values are serialized.
You supply your own. `serde_json` is one option.

## Transactions

A `sqlx::Transaction` dereferences to a `SqliteConnection`, so a provider can run
against an open transaction by passing `&mut *transaction`. Every write the
provider performs is then part of that transaction and commits or rolls back
together with your application's own writes against the same database:

```rust,ignore
let mut transaction = connection.begin().await?;

// The provider borrows the transaction, so scope it and drop it before using
// the transaction directly again.
{
    let storage = SqliteStorageProvider::<JsonCodec>::new(&mut transaction);
    storage.write_signature_key_pair(&public_key, &key_pair)?;
}

// An application write that shares the same transaction.
sqlx::query("INSERT INTO accounts (name, key) VALUES (?, ?)")
    .bind("alice")
    .bind(&public_key.0)
    .execute(&mut *transaction)
    .await?;

// Both writes commit atomically. `transaction.rollback()` would discard both.
transaction.commit().await?;
```

Run the migrations on the bare connection rather than inside a transaction, so
that the schema is not tied to the lifetime of a single transaction.

A complete, runnable version of this is in
[`examples/transaction.rs`](examples/transaction.rs):

```sh
cargo run --example transaction
```

## Runtime

The provider exposes a synchronous API and drives the underlying async `sqlx`
calls internally with `tokio::task::block_in_place`. It therefore has to run on
a multi-threaded tokio runtime (`#[tokio::main(flavor = "multi_thread")]` or
`#[tokio::test(flavor = "multi_thread")]`).
