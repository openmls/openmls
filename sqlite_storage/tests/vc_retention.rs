#![cfg(feature = "virtual-clients-draft")]

use openmls_sqlite_storage::Codec;
use openmls_traits::storage::{
    traits::{self},
    Entity, Key, StorageProvider,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: serde::de::DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

// Test types
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupId(Vec<u8>);
impl traits::GroupId<1> for TestGroupId {}
impl Key<1> for TestGroupId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestEpochId(Vec<u8>);
impl traits::VcEpochId<1> for TestEpochId {}
impl Key<1> for TestEpochId {}
impl Entity<1> for TestEpochId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestRetentionState(Vec<u8>);
impl traits::VcRetentionState<1> for TestRetentionState {}
impl Entity<1> for TestRetentionState {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestEpochRefs(Vec<u8>);
impl traits::VcEpochRefs<1> for TestEpochRefs {}
impl Entity<1> for TestEpochRefs {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestCreationTracking(Vec<u8>);
impl traits::VcCreationTracking<1> for TestCreationTracking {}
impl Entity<1> for TestCreationTracking {}

fn storage() -> openmls_sqlite_storage::SqliteStorageProvider<JsonCodec, Connection> {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    let mut storage =
        openmls_sqlite_storage::SqliteStorageProvider::<JsonCodec, Connection>::new(connection);
    storage.run_migrations().unwrap();
    storage
}

/// Write, read back, overwrite, and delete the retention state of an emulation
/// group.
#[test]
fn retention_state_read_write_delete() {
    let storage = storage();
    let group_id = TestGroupId(b"TestGroupId".to_vec());

    // Nothing is stored initially.
    let read: Option<TestRetentionState> = storage.vc_retention_state(&group_id).unwrap();
    assert_eq!(read, None);

    // Write and read back.
    let state = TestRetentionState(b"TestRetentionState".to_vec());
    storage.write_vc_retention_state(&group_id, &state).unwrap();
    let read: Option<TestRetentionState> = storage.vc_retention_state(&group_id).unwrap();
    assert_eq!(read, Some(state));

    // A second write replaces the stored state.
    let updated_state = TestRetentionState(b"UpdatedRetentionState".to_vec());
    storage
        .write_vc_retention_state(&group_id, &updated_state)
        .unwrap();
    let read: Option<TestRetentionState> = storage.vc_retention_state(&group_id).unwrap();
    assert_eq!(read, Some(updated_state));

    // A different group id reads nothing.
    let other_group_id = TestGroupId(b"OtherGroupId".to_vec());
    let read: Option<TestRetentionState> = storage.vc_retention_state(&other_group_id).unwrap();
    assert_eq!(read, None);

    // Delete removes the state.
    storage.delete_vc_retention_state(&group_id).unwrap();
    let read: Option<TestRetentionState> = storage.vc_retention_state(&group_id).unwrap();
    assert_eq!(read, None);
}

/// Write, read back, overwrite, and delete the reverse reference index of a
/// derivation epoch.
#[test]
fn epoch_refs_read_write_delete() {
    let storage = storage();
    let epoch_id = TestEpochId(b"TestEpochId".to_vec());

    // Nothing is stored initially.
    let read: Option<TestEpochRefs> = storage.vc_epoch_refs(&epoch_id).unwrap();
    assert_eq!(read, None);

    // Write and read back.
    let refs = TestEpochRefs(b"TestEpochRefs".to_vec());
    storage.write_vc_epoch_refs(&epoch_id, &refs).unwrap();
    let read: Option<TestEpochRefs> = storage.vc_epoch_refs(&epoch_id).unwrap();
    assert_eq!(read, Some(refs));

    // A second write replaces the stored index.
    let updated_refs = TestEpochRefs(b"UpdatedEpochRefs".to_vec());
    storage
        .write_vc_epoch_refs(&epoch_id, &updated_refs)
        .unwrap();
    let read: Option<TestEpochRefs> = storage.vc_epoch_refs(&epoch_id).unwrap();
    assert_eq!(read, Some(updated_refs));

    // A different epoch id reads nothing.
    let other_epoch_id = TestEpochId(b"OtherEpochId".to_vec());
    let read: Option<TestEpochRefs> = storage.vc_epoch_refs(&other_epoch_id).unwrap();
    assert_eq!(read, None);

    // Delete removes the index.
    storage.delete_vc_epoch_refs(&epoch_id).unwrap();
    let read: Option<TestEpochRefs> = storage.vc_epoch_refs(&epoch_id).unwrap();
    assert_eq!(read, None);
}

/// Write, read back, overwrite, and delete the creation tracking of a
/// higher-level group.
#[test]
fn creation_tracking_read_write_delete() {
    let storage = storage();
    let group_id = TestGroupId(b"TestGroupId".to_vec());

    // Nothing is stored initially.
    let read: Option<TestCreationTracking> = storage.vc_creation_tracking(&group_id).unwrap();
    assert_eq!(read, None);

    // Write and read back.
    let tracking = TestCreationTracking(b"TestCreationTracking".to_vec());
    storage
        .write_vc_creation_tracking(&group_id, &tracking)
        .unwrap();
    let read: Option<TestCreationTracking> = storage.vc_creation_tracking(&group_id).unwrap();
    assert_eq!(read, Some(tracking));

    // A second write replaces the stored tracking.
    let updated_tracking = TestCreationTracking(b"UpdatedCreationTracking".to_vec());
    storage
        .write_vc_creation_tracking(&group_id, &updated_tracking)
        .unwrap();
    let read: Option<TestCreationTracking> = storage.vc_creation_tracking(&group_id).unwrap();
    assert_eq!(read, Some(updated_tracking));

    // A different group id reads nothing.
    let other_group_id = TestGroupId(b"OtherGroupId".to_vec());
    let read: Option<TestCreationTracking> = storage.vc_creation_tracking(&other_group_id).unwrap();
    assert_eq!(read, None);

    // Delete removes the tracking.
    storage.delete_vc_creation_tracking(&group_id).unwrap();
    let read: Option<TestCreationTracking> = storage.vc_creation_tracking(&group_id).unwrap();
    assert_eq!(read, None);
}
