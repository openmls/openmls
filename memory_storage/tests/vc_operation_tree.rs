#![cfg(feature = "virtual-clients-draft")]

use openmls_memory_storage::MemoryStorage;
use openmls_traits::storage::{
    traits::{self},
    Entity, Key, StorageProvider, CURRENT_VERSION,
};
use serde::{Deserialize, Serialize};

// Test types
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestEpochId(Vec<u8>);
impl traits::VcEpochId<CURRENT_VERSION> for TestEpochId {}
impl Key<CURRENT_VERSION> for TestEpochId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestOperationTree(Vec<u8>);
impl traits::VcOperationTree<CURRENT_VERSION> for TestOperationTree {}
impl Entity<CURRENT_VERSION> for TestOperationTree {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestKeyPackageRef(Vec<u8>);
impl traits::HashReference<CURRENT_VERSION> for TestKeyPackageRef {}
impl Key<CURRENT_VERSION> for TestKeyPackageRef {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestRetainedMaterial(Vec<u8>);
impl traits::RetainedKeyPackageMaterial<CURRENT_VERSION> for TestRetainedMaterial {}
impl Entity<CURRENT_VERSION> for TestRetainedMaterial {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestDerivationState(Vec<u8>);
impl traits::VcDerivationEpochState<CURRENT_VERSION> for TestDerivationState {}
impl Entity<CURRENT_VERSION> for TestDerivationState {}

/// A batch write stores the operation tree and the retained material, and the
/// material makes the epoch report as referenced until it is deleted.
#[test]
fn batch_write_ties_retained_material_into_epoch_liveness() {
    let storage = MemoryStorage::default();
    let epoch_id = TestEpochId(b"LiveEpoch".to_vec());
    let other_epoch_id = TestEpochId(b"OtherEpoch".to_vec());
    let kp_ref = TestKeyPackageRef(b"kp-ref".to_vec());

    // Register the derivation epoch state so the delete has something to
    // remove. The operation tree is written by the batch below.
    storage
        .write_vc_derivation_epoch_state(&epoch_id, &TestDerivationState(b"state".to_vec()))
        .unwrap();

    // No retained material yet.
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

    // The batch wrote both the tree and the material.
    let read_tree: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read_tree, Some(tree));
    let read_material: Option<TestRetainedMaterial> =
        storage.retained_key_package_material(&kp_ref).unwrap();
    assert_eq!(read_material, Some(material));

    // The epoch is now referenced, a different epoch is not.
    assert!(storage
        .has_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap());
    assert!(!storage
        .has_retained_key_package_material_for_epoch(&other_epoch_id)
        .unwrap());

    // The delete is unconditional. It removes both the epoch state and the
    // operation tree even though material still references the epoch.
    storage.delete_vc_derivation_epoch_state(&epoch_id).unwrap();
    let read_state: Option<TestDerivationState> =
        storage.vc_derivation_epoch_state(&epoch_id).unwrap();
    assert!(read_state.is_none());
    let read_tree: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert!(read_tree.is_none());

    // The material is independent of the epoch state. It keeps reporting the
    // epoch as referenced until it is deleted itself.
    assert!(storage
        .has_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap());
    storage
        .delete_retained_key_package_material(&kp_ref)
        .unwrap();
    assert!(!storage
        .has_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap());
}

/// Deleting the retained material of one epoch leaves another epoch's material
/// alone. This is what tearing down an emulation group needs: the material is
/// keyed by KeyPackage reference, which the caller cannot enumerate.
#[test]
fn retained_material_is_deletable_per_epoch() {
    let storage = MemoryStorage::default();
    let epoch_id = TestEpochId(b"TornDownEpoch".to_vec());
    let other_epoch_id = TestEpochId(b"SurvivingEpoch".to_vec());
    let first_ref = TestKeyPackageRef(b"kp-ref-1".to_vec());
    let second_ref = TestKeyPackageRef(b"kp-ref-2".to_vec());
    let other_ref = TestKeyPackageRef(b"kp-ref-other".to_vec());
    let material = TestRetainedMaterial(b"material".to_vec());

    storage
        .write_retained_key_package_material_batch(
            &epoch_id,
            &TestOperationTree(b"tree".to_vec()),
            &[
                (first_ref.clone(), material.clone()),
                (second_ref.clone(), material.clone()),
            ],
        )
        .unwrap();
    storage
        .write_retained_key_package_material_batch(
            &other_epoch_id,
            &TestOperationTree(b"other tree".to_vec()),
            &[(other_ref.clone(), material.clone())],
        )
        .unwrap();

    storage
        .delete_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap();

    // Both materials of the epoch are gone, by reference and by epoch tag.
    for kp_ref in [&first_ref, &second_ref] {
        let read: Option<TestRetainedMaterial> =
            storage.retained_key_package_material(kp_ref).unwrap();
        assert!(read.is_none());
    }
    assert!(!storage
        .has_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap());

    // The other epoch keeps its material.
    let read: Option<TestRetainedMaterial> =
        storage.retained_key_package_material(&other_ref).unwrap();
    assert_eq!(read, Some(material));
    assert!(storage
        .has_retained_key_package_material_for_epoch(&other_epoch_id)
        .unwrap());

    // Deleting an epoch that has no material is a no-op.
    storage
        .delete_retained_key_package_material_for_epoch(&epoch_id)
        .unwrap();
}

/// Write, read back, overwrite, and delete an operation secret tree.
#[test]
fn operation_tree_read_write_delete() {
    let storage = MemoryStorage::default();
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

    // Deleting the derivation epoch state removes the operation tree too.
    storage.delete_vc_derivation_epoch_state(&epoch_id).unwrap();
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, None);
}
