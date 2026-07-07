# Storage migration

[comment]: <> (TODO: add overview)

The `openmls_storage_migration::StorageMigrationHelper` trait must be implemented on the
`StorageProvider`. The `group_ids()` method enumerates all stored `GroupId`s that are used as
keys in the provider.

```rust,no_run,noplayground
{{#include ../../../compat_tests/src/test_storage_provider.rs:migration_helper_impl}}
```

Then, the migration methods available in `openmls::storage::migration`
(behind the `storage_migration` feature flag) can be called in order to migrate records from the previous version
to the current version. Records that have already been migrated are not modified.

```rust,no_run,noplayground
{{#include ../../../compat_tests/tests/storage_migration_book_code.rs:storage_migration}}
```
