#![allow(dead_code)]
#![cfg(feature = "storage_migration")]
//! Test storage migration using a non-self-describing format

use openmls_compat_tests::test_storage_provider::TestStorageProvider;
use openmls_storage_migration::StorageMigrationError;
use openmls_traits::storage::StorageProvider;
use openmls_traits_0_4_1::storage::StorageProvider as StorageProvider_0_4_1;

const TEST_GROUP_STATE: &str = include_str!("data/mls_group_state.json");
const TEST_MESSAGE_SECRETS_STORE: &str = include_str!("data/message_secrets_store.json");

const GROUP_ID_BYTES: &[u8] = b"group_id_bytes";

/// Helper function for testing storage migration from Legacy -> Current when formats are
/// incompatible
fn test_migration<
    'a,
    KeyCurrent,
    KeyLegacy,
    Current: serde::Deserialize<'a>,
    Legacy: serde::Serialize + serde::Deserialize<'a>,
>(
    storage: &TestStorageProvider,
    input: &'a str,
    key_legacy: &KeyLegacy,
    key_current: &KeyCurrent,
    write: impl Fn(&TestStorageProvider, &KeyLegacy, &Legacy) -> Result<(), postcard::Error>,
    read: impl Fn(&TestStorageProvider, &KeyCurrent) -> Result<Option<Current>, postcard::Error>,
    migrate: impl Fn(
        &TestStorageProvider,
    ) -> Result<(), StorageMigrationError<postcard::Error, postcard::Error>>,
) {
    // deserialize the input data from JSON
    let input: Legacy = serde_json::from_str(input).expect("error deserializing input");

    // write to storage
    write(storage, key_legacy, &input).unwrap();

    // reading from storage using new format fails
    assert!(read(storage, key_current).is_err());

    // migrate
    migrate(storage).unwrap();

    // reading from storage using new format succeeds
    assert!(read(storage, key_current).is_ok());
}

/// Helper function for testing tolerant deserialization from Legacy -> Current when formats are
/// backwards-compatible
fn test_tolerant_deserialization<
    'a,
    KeyCurrent,
    KeyLegacy,
    Current: serde::Deserialize<'a>,
    Legacy: serde::Serialize + serde::Deserialize<'a>,
>(
    storage: &TestStorageProvider,
    input: &'a str,
    key_legacy: &KeyLegacy,
    key_current: &KeyCurrent,
    write: impl Fn(&TestStorageProvider, &KeyLegacy, &Legacy) -> Result<(), postcard::Error>,
    read: impl Fn(&TestStorageProvider, &KeyCurrent) -> Result<Option<Current>, postcard::Error>,
) {
    // deserialize the input data from JSON
    let input: Legacy = serde_json::from_str(input).expect("error deserializing input");

    // write to storage
    write(storage, key_legacy, &input).unwrap();

    // reading from storage using new format succeeds
    assert!(read(storage, key_current).is_ok());
}

#[test]
/// Test storage migration with a non-self-describing format (0.7.x -> current)
fn test_storage_migration() {
    // create group ids
    let group_id_0_7 = openmls_0_7::prelude::GroupId::from_slice(GROUP_ID_BYTES);
    let group_id = openmls::prelude::GroupId::from_slice(GROUP_ID_BYTES);
    // initialize test storage provider
    let storage_provider = TestStorageProvider::default();

    // test migration of group state
    test_migration::<_, _, openmls::prelude::MlsGroupState, openmls_0_7::prelude::MlsGroupState>(
        &storage_provider,
        TEST_GROUP_STATE,
        &group_id_0_7,
        &group_id,
        StorageProvider_0_4_1::write_group_state,
        StorageProvider::group_state,
        openmls::storage::migration::migrate_group_state,
    );

    // test deserialization of MessageSecretsStore
    test_tolerant_deserialization::<
        _,
        _,
        openmls::storage::migration::MessageSecretsStore,
        openmls::storage::migration::MessageSecretsStoreCompat,
    >(
        &storage_provider,
        TEST_MESSAGE_SECRETS_STORE,
        &group_id,
        &group_id,
        StorageProvider::write_message_secrets,
        StorageProvider::message_secrets,
    );
}
