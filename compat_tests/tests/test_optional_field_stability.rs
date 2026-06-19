//! Test serialization of MlsGroupState using the storage provider
#![allow(dead_code)]
#![cfg(feature = "optional_field_stability")]

use openmls_compat_tests::test_storage_provider::TestStorageProvider;
use openmls_traits::storage::StorageProvider;
use openmls_traits_0_4_1::storage::StorageProvider as StorageProvider_0_4_1;

const TEST_DATA: &'static str = include_str!("data/mls_group_state.json");

const GROUP_ID_BYTES: &[u8] = b"group_id_bytes";

#[test]
/// Test deserialization of an `MlsGroupState` across `openmls` versions (0.7.0 -> current)
fn test_optional_field_stability() {
    let storage_provider = TestStorageProvider::default();

    let group_state_earlier_version: openmls_0_7_0::prelude::MlsGroupState =
        serde_json::from_str(TEST_DATA).unwrap();
    let group_id_earlier_version = openmls_0_7_0::prelude::GroupId::from_slice(GROUP_ID_BYTES);
    let group_id = openmls::prelude::GroupId::from_slice(GROUP_ID_BYTES);

    // serialize openmls_0_7_0::prelude::MlsGroupState
    StorageProvider_0_4_1::write_group_state(
        &storage_provider,
        &group_id_earlier_version,
        &group_state_earlier_version,
    )
    .unwrap();

    // deserialize as `openmls::prelude::MlsGroupState`
    let _group_state_converted: Option<openmls::prelude::MlsGroupState> =
        StorageProvider::group_state_compat::<_, openmls::group::MlsGroupStateCompat, _>(
            &storage_provider,
            &group_id,
        )
        .unwrap();
}
