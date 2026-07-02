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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestKeyPackageRef(Vec<u8>);
impl traits::HashReference<1> for TestKeyPackageRef {}
impl Key<1> for TestKeyPackageRef {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestRetainedMaterial(Vec<u8>);
impl traits::RetainedKeyPackageMaterial<1> for TestRetainedMaterial {}
impl Entity<1> for TestRetainedMaterial {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestEmulationState(Vec<u8>);
impl traits::VcEmulationEpochState<1> for TestEmulationState {}
impl Entity<1> for TestEmulationState {}

/// A batch write stores the operation tree and the retained material, the
/// material ties the epoch into liveness, and the guarded delete keeps the
/// epoch state while material references it but removes it afterwards.
#[test]
fn batch_write_ties_retained_material_into_epoch_liveness() {
    let storage = storage();
    let epoch_id = TestEpochId(b"LiveEpoch".to_vec());
    let other_epoch_id = TestEpochId(b"OtherEpoch".to_vec());
    let kp_ref = TestKeyPackageRef(b"kp-ref".to_vec());

    storage
        .write_vc_emulation_epoch_state(&epoch_id, &TestEmulationState(b"state".to_vec()))
        .unwrap();

    assert!(!storage
        .has_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap());

    let tree = TestOperationTree(b"AdvancedTree".to_vec());
    let material = TestRetainedMaterial(b"material".to_vec());
    storage
        .write_retained_key_package_material_batch(
            &epoch_id,
            &tree,
            &[(kp_ref.clone(), material.clone())],
        )
        .unwrap();

    let read_tree: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read_tree, Some(tree));
    let read_material: Option<TestRetainedMaterial> =
        storage.retained_key_package_material(&kp_ref).unwrap();
    assert_eq!(read_material, Some(material));

    assert!(storage
        .has_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap());
    assert!(!storage
        .has_retained_key_package_material_for_epoch(&other_epoch_id)
        .unwrap());

    // While material references the epoch the guarded delete is a no-op.
    assert!(!storage
        .delete_vc_emulation_state_if_unreferenced(&epoch_id)
        .unwrap());
    let read_state: Option<TestEmulationState> =
        storage.vc_emulation_epoch_state(&epoch_id).unwrap();
    assert!(read_state.is_some());
    let read_tree: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert!(read_tree.is_some());

    // After deleting the material the guarded delete removes the epoch state
    // and the operation tree.
    storage
        .delete_retained_key_package_material(&kp_ref)
        .unwrap();
    assert!(!storage
        .has_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap());
    assert!(storage
        .delete_vc_emulation_state_if_unreferenced(&epoch_id)
        .unwrap());
    let read_state: Option<TestEmulationState> =
        storage.vc_emulation_epoch_state(&epoch_id).unwrap();
    assert!(read_state.is_none());
    let read_tree: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert!(read_tree.is_none());
}

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

    // Deleting the emulation state removes the operation tree too. No retained
    // material references this epoch, so the deletion goes through.
    let deleted = storage
        .delete_vc_emulation_state_if_unreferenced(&epoch_id)
        .unwrap();
    assert!(deleted);
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, None);
}
