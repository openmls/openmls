//! Test serialization of MlsGroupState using the storage provider
#![allow(dead_code)]
#![cfg(feature = "optional_field_stability")]

use openmls_compat_tests::test_storage_provider::TestStorageProvider;
use openmls_storage_migration::StorageMigrationHelper;
use openmls_traits::storage::StorageProvider;
use openmls_traits_0_4_1::storage::StorageProvider as StorageProvider_0_4_1;

const TEST_GROUP_STATE: &str = include_str!("data/mls_group_state.json");

const GROUP_ID_BYTES: &[u8] = b"group_id_bytes";

#[test]
/// Test deserialization of an `MlsGroupState` across `openmls` versions (0.7.0 -> current)
fn test_optional_field_stability() {
    // create group ids
    let group_id_0_7_0 = openmls_0_7_0::prelude::GroupId::from_slice(GROUP_ID_BYTES);
    let group_id = openmls::prelude::GroupId::from_slice(GROUP_ID_BYTES);

    // initialize test storage provider
    let storage_provider = TestStorageProvider::default();

    // deserialize the input data from JSON
    let group_state_0_7_0: openmls_0_7_0::prelude::MlsGroupState =
        serde_json::from_str(TEST_GROUP_STATE).expect("error deserializing group state");

    // write the group state to the storage provider
    StorageProvider_0_4_1::write_group_state(
        &storage_provider,
        &group_id_0_7_0,
        &group_state_0_7_0,
    )
    .unwrap();

    // deserialize with non-compat type fails
    StorageProvider::group_state::<openmls::group::MlsGroupState, _>(&storage_provider, &group_id)
        .unwrap_err();

    // perform migration
    openmls::storage::migration::migrate_group_state(&storage_provider).unwrap();
    openmls::storage::migration::migrate_message_secrets(&storage_provider).unwrap();

    // deserialize with non-compat type succeeds
    StorageProvider::group_state::<openmls::group::MlsGroupState, _>(&storage_provider, &group_id)
        .unwrap();

    // TODO: test MessageSecretsStore migration
}
