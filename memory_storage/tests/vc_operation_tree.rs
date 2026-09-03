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
impl Entity<CURRENT_VERSION> for TestEpochId {}

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

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupId(Vec<u8>);
impl traits::GroupId<CURRENT_VERSION> for TestGroupId {}
impl Key<CURRENT_VERSION> for TestGroupId {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupEpoch(u64);
impl traits::EpochKey<CURRENT_VERSION> for TestGroupEpoch {}
impl Key<CURRENT_VERSION> for TestGroupEpoch {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestBinding(Vec<u8>);
impl traits::VcEmulationBinding<CURRENT_VERSION> for TestBinding {}
impl Entity<CURRENT_VERSION> for TestBinding {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestLogEntry(Vec<u8>);
impl traits::VcDerivationEpochLogEntry<CURRENT_VERSION> for TestLogEntry {}
impl Entity<CURRENT_VERSION> for TestLogEntry {}

fn sweep(storage: &MemoryStorage) -> Vec<TestEpochId> {
    storage
        .delete_unreferenced_vc_derivation_epoch_states()
        .unwrap()
}

#[test]
fn logged_epochs_keep_epoch_state_alive() {
    let storage = MemoryStorage::default();
    let pruned_epoch_id = TestEpochId(b"PrunedEpoch".to_vec());
    let newest_epoch_id = TestEpochId(b"NewestEpoch".to_vec());
    let group_id = TestGroupId(b"emulation-group".to_vec());

    for (epoch_id, entry) in [
        (&pruned_epoch_id, b"entry-0".to_vec()),
        (&newest_epoch_id, b"entry-1".to_vec()),
    ] {
        storage
            .write_vc_derivation_epoch_state(epoch_id, &TestDerivationState(b"state".to_vec()))
            .unwrap();
        storage
            .write_vc_derivation_epoch_log_entry(&group_id, epoch_id, &TestLogEntry(entry))
            .unwrap();
    }
    let mut entries: Vec<TestLogEntry> =
        storage.vc_derivation_epoch_log_entries(&group_id).unwrap();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        entries,
        vec![
            TestLogEntry(b"entry-0".to_vec()),
            TestLogEntry(b"entry-1".to_vec())
        ]
    );

    // Nothing else references either epoch, so the log entries alone keep both
    // states.
    assert!(sweep(&storage).is_empty());
    for epoch_id in [&pruned_epoch_id, &newest_epoch_id] {
        let read_state: Option<TestDerivationState> =
            storage.vc_derivation_epoch_state(epoch_id).unwrap();
        assert!(read_state.is_some());
    }

    // Pruning one entry releases exactly that epoch on the next sweep.
    storage
        .delete_vc_derivation_epoch_log_entries(&group_id, std::slice::from_ref(&pruned_epoch_id))
        .unwrap();
    assert_eq!(sweep(&storage), vec![pruned_epoch_id.clone()]);
    let read_state: Option<TestDerivationState> =
        storage.vc_derivation_epoch_state(&pruned_epoch_id).unwrap();
    assert!(read_state.is_none());

    // Deleting the whole log releases the remaining epoch.
    storage.delete_vc_derivation_epoch_log(&group_id).unwrap();
    let entries: Vec<TestLogEntry> = storage.vc_derivation_epoch_log_entries(&group_id).unwrap();
    assert!(entries.is_empty());
    assert_eq!(sweep(&storage), vec![newest_epoch_id]);
}

#[test]
fn emulation_binding_keeps_epoch_state_alive() {
    let storage = MemoryStorage::default();
    let first_epoch_id = TestEpochId(b"FirstBoundEpoch".to_vec());
    let second_epoch_id = TestEpochId(b"SecondBoundEpoch".to_vec());
    let group_id = TestGroupId(b"group".to_vec());

    for (epoch_id, group_epoch, binding) in [
        (&first_epoch_id, TestGroupEpoch(5), b"binding-5".to_vec()),
        (&second_epoch_id, TestGroupEpoch(6), b"binding-6".to_vec()),
    ] {
        storage
            .write_vc_derivation_epoch_state(epoch_id, &TestDerivationState(b"state".to_vec()))
            .unwrap();
        storage
            .write_vc_emulation_binding(&group_id, &group_epoch, epoch_id, &TestBinding(binding))
            .unwrap();
    }

    // The point get serves each binding under its own group epoch.
    let read: Option<TestBinding> = storage
        .vc_emulation_binding(&group_id, &TestGroupEpoch(5))
        .unwrap();
    assert_eq!(read, Some(TestBinding(b"binding-5".to_vec())));
    let read: Option<TestBinding> = storage
        .vc_emulation_binding(&group_id, &TestGroupEpoch(7))
        .unwrap();
    assert_eq!(read, None);
    let all: Vec<TestBinding> = storage.vc_emulation_bindings(&group_id).unwrap();
    assert_eq!(all.len(), 2);

    // No retained material references the epochs, so the bindings alone keep
    // the states.
    assert!(sweep(&storage).is_empty());

    // A targeted delete of the first binding releases only the first epoch.
    storage
        .delete_vc_emulation_bindings(&group_id, &[TestGroupEpoch(5)])
        .unwrap();
    assert_eq!(sweep(&storage), vec![first_epoch_id]);

    // Deleting all bindings of the group releases the second epoch too.
    storage.delete_all_vc_emulation_bindings(&group_id).unwrap();
    let all: Vec<TestBinding> = storage.vc_emulation_bindings(&group_id).unwrap();
    assert!(all.is_empty());
    assert_eq!(sweep(&storage), vec![second_epoch_id.clone()]);
    let read_state: Option<TestDerivationState> =
        storage.vc_derivation_epoch_state(&second_epoch_id).unwrap();
    assert!(read_state.is_none());
}

#[test]
fn batch_write_ties_retained_material_into_epoch_liveness() {
    let storage = MemoryStorage::default();
    let epoch_id = TestEpochId(b"LiveEpoch".to_vec());
    let kp_ref = TestKeyPackageRef(b"kp-ref".to_vec());

    // Register the derivation epoch state so the sweep has something to
    // remove. The operation tree is written by the batch below.
    storage
        .write_vc_derivation_epoch_state(&epoch_id, &TestDerivationState(b"state".to_vec()))
        .unwrap();

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

    // While material references the epoch the sweep leaves it alone and the
    // epoch state and tree stay readable.
    assert!(sweep(&storage).is_empty());
    let read_state: Option<TestDerivationState> =
        storage.vc_derivation_epoch_state(&epoch_id).unwrap();
    assert!(read_state.is_some());
    let read_tree: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert!(read_tree.is_some());

    // After deleting the material the epoch is unreferenced, so the sweep
    // removes both the epoch state and the operation tree.
    storage
        .delete_retained_key_package_material(&kp_ref)
        .unwrap();
    assert_eq!(sweep(&storage), vec![epoch_id.clone()]);
    let read_state: Option<TestDerivationState> =
        storage.vc_derivation_epoch_state(&epoch_id).unwrap();
    assert!(read_state.is_none());
    let read_tree: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert!(read_tree.is_none());
}

#[test]
fn operation_tree_read_write_sweep() {
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

    // The tree row has no state, log entry, binding, or material next to it,
    // which is what a crashed registration leaves behind. The sweep collects
    // it.
    assert_eq!(sweep(&storage), vec![epoch_id.clone()]);
    let read: Option<TestOperationTree> = storage.vc_operation_tree(&epoch_id).unwrap();
    assert_eq!(read, None);
}
