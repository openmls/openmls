#![cfg(feature = "storage_migration")]

use openmls_compat_tests::test_storage_provider::TestStorageProvider;

#[test]
fn storage_migration_book_example() {
    let provider = &TestStorageProvider::default();

    // ANCHOR: storage_migration
    openmls::storage::migration::migrate_group_state(provider)
        .expect("storage migration of MlsGroupState failed");
    // ANCHOR_END: storage_migration
}
