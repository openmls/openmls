//! Utils for compat tests

pub mod storage_tag_check;

#[cfg(any(feature = "storage_migration_0_7", feature = "storage_migration_0_8"))]
pub mod test_crypto_provider;

#[cfg(any(feature = "storage_migration_0_7", feature = "storage_migration_0_8"))]
pub mod test_storage_provider;
