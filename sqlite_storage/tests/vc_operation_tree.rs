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
struct TestEpochId(Vec<u8>);
impl traits::VcEpochId<1> for TestEpochId {}
impl Key<1> for TestEpochId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestOperationTree(Vec<u8>);
impl traits::VcOperationTree<1> for TestOperationTree {}
impl Entity<1> for TestOperationTree {}

fn storage() -> openmls_sqlite_storage::SqliteStorageProvider<JsonCodec, Connection> {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    let mut storage =
        openmls_sqlite_storage::SqliteStorageProvider::<JsonCodec, Connection>::new(connection);
    storage.run_migrations().unwrap();
    storage
}

/// Write, read back, overwrite, and delete an operation secret tree.
#[test]
fn operation_tree_read_write_delete() {
    let storage = storage();
    let epoch_id = TestEpochId(b"TestEpochId".to_vec());

    // Nothing is stored initially.
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, None);

    // Write and read back.
    let tree = TestOperationTree(b"TestOperationTree".to_vec());
    storage.write_vc_operation_tree(&epoch_id, &tree).unwrap();
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, Some(tree));

    // A second write replaces the stored tree (write-back after a ratchet
    // advance).
    let advanced_tree = TestOperationTree(b"AdvancedOperationTree".to_vec());
    storage
        .write_vc_operation_tree(&epoch_id, &advanced_tree)
        .unwrap();
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, Some(advanced_tree));

    // A different epoch id reads nothing.
    let other_epoch_id = TestEpochId(b"OtherEpochId".to_vec());
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&other_epoch_id).unwrap();
    assert_eq!(read, None);

    // Deleting the emulation state removes the operation tree too.
    storage.delete_vc_emulation_state(&epoch_id).unwrap();
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, None);
}
