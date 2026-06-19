//! Test serialization of MlsGroupState using the storage provider
#![allow(dead_code)]
#![cfg(feature = "optional_field_stability")]

use openmls_compat_tests::test_storage_provider::TestStorageProvider;
use openmls_traits::storage::StorageProvider;
use openmls_traits_0_4_1::storage::StorageProvider as StorageProvider_0_4_1;

const TEST_DATA: &'static str = include_str!("data/mls_group_state.json");

#[test]
/// Test deserialization of an `MlsGroupState` across `openmls` versions (0.7.0 -> current)
fn test_optional_field_stability() {
    let group_state_compat: openmls_0_7_0::prelude::MlsGroupState =
        serde_json::from_str(TEST_DATA).unwrap();
    let group_id_compat = openmls_0_7_0::prelude::GroupId::from_slice(GROUP_ID_BYTES);

    // check serialization of openmls_0_7_0::prelude::MlsGroupState
    StorageProvider_0_4_1::write_group_state(
        &storage_provider,
        &group_id_compat,
        &group_state_compat,
    )
    .unwrap();
    let group_state_from_earlier_version: Option<openmls::prelude::MlsGroupState> =
        StorageProvider::group_state_compat::<_, openmls::group::MlsGroupStateCompat, _>(
            &storage_provider,
            &group_id,
        )
        .unwrap();

    // compare the group states
    assert_eq!(
        serde_json::to_string(&group_state_from_compat).unwrap(),
        serde_json::to_string(&group_state_from_earlier_version).unwrap()
    );
}
