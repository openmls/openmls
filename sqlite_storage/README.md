# OpenMLS SQLite Storage

A codec-independent SQLite storage provider implementing the `StorageProvider` trait from `openmls_traits` using the `rusqlite` crate.

This crate provides two execution modes:

- `SqliteStorageProvider<C, ConnectionRef>` for normal SQLite-backed storage operations
- `TransactionalSqliteStorageProvider<'tx, C>` for storage operations bound to an active `rusqlite::Transaction`

## Transaction API

Use `SqliteStorageProvider::transaction(...)` to execute multi-step storage operations inside a single SQLite transaction.

```rust
use openmls_sqlite_storage::SqliteStorageProvider;

let mut storage = SqliteStorageProvider::<MyCodec, _>::new(connection);
storage.run_migrations()?;

storage.transaction(|tx_storage| {
    // All reads and writes performed through `tx_storage`
    // are part of the same SQLite transaction.
    Ok(())
})?;
```

If the closure returns `Ok(_)`, the transaction is committed.
If the closure returns `Err(_)`, the transaction is rolled back.
