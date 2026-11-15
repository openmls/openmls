use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
use openmls_traits::storage::{traits, Entity, Key, StorageProvider, CURRENT_VERSION};
use serde::{Deserialize, Serialize};

// A byte vector catches both JSON type mismatches and out-of-range bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TestValue(Vec<u8>);

impl Key<CURRENT_VERSION> for TestValue {}
impl Entity<CURRENT_VERSION> for TestValue {}
impl traits::GroupId<CURRENT_VERSION> for TestValue {}
impl traits::SignaturePublicKey<CURRENT_VERSION> for TestValue {}
impl traits::EpochKey<CURRENT_VERSION> for TestValue {}
impl traits::TreeSync<CURRENT_VERSION> for TestValue {}
impl traits::GroupContext<CURRENT_VERSION> for TestValue {}
impl traits::InterimTranscriptHash<CURRENT_VERSION> for TestValue {}
impl traits::ConfirmationTag<CURRENT_VERSION> for TestValue {}
impl traits::SignatureKeyPair<CURRENT_VERSION> for TestValue {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for TestValue {}
impl traits::LeafNode<CURRENT_VERSION> for TestValue {}

#[cfg(feature = "extensions-draft")]
impl traits::ApplicationExportTree<CURRENT_VERSION> for TestValue {}
#[cfg(feature = "virtual-clients-draft")]
impl traits::VcEpochId<CURRENT_VERSION> for TestValue {}
#[cfg(feature = "virtual-clients-draft")]
impl traits::VcDerivationEpochState<CURRENT_VERSION> for TestValue {}
#[cfg(feature = "virtual-clients-draft")]
impl traits::VcOperationTree<CURRENT_VERSION> for TestValue {}
#[cfg(feature = "virtual-clients-draft")]
impl traits::HashReference<CURRENT_VERSION> for TestValue {}
#[cfg(feature = "virtual-clients-draft")]
impl traits::RetainedKeyPackageMaterial<CURRENT_VERSION> for TestValue {}

const CORRUPTED_VALUES: &[&[u8]] = &[b"[44251]", b"{}", b"\"x\"", b"[", b"[[44251]]"];

fn corrupt_only_value(storage: &MemoryStorage, corrupted: &[u8]) {
    let mut values = storage.values.write().unwrap();
    assert_eq!(values.len(), 1);
    *values.values_mut().next().unwrap() = corrupted.to_vec();
}

macro_rules! test_optional_reader {
    ($name:ident, $write:ident, $read:ident) => {
        #[test]
        fn $name() {
            let storage = MemoryStorage::default();
            let key = TestValue(vec![1]);
            let value = TestValue(vec![2, 3]);

            assert_eq!(storage.$read::<_, TestValue>(&key), Ok(None));
            storage.$write(&key, &value).unwrap();
            assert_eq!(storage.$read(&key), Ok(Some(value)));

            for corrupted in CORRUPTED_VALUES {
                corrupt_only_value(&storage, corrupted);
                assert_eq!(
                    storage.$read::<_, TestValue>(&key),
                    Err(MemoryStorageError::SerializationError),
                    "accepted corrupted value: {corrupted:?}"
                );
            }
        }
    };
}

test_optional_reader!(corrupted_tree, write_tree, tree);
test_optional_reader!(corrupted_group_context, write_context, group_context);
test_optional_reader!(
    corrupted_interim_transcript_hash,
    write_interim_transcript_hash,
    interim_transcript_hash
);
test_optional_reader!(
    corrupted_confirmation_tag,
    write_confirmation_tag,
    confirmation_tag
);
test_optional_reader!(
    corrupted_signature_key_pair,
    write_signature_key_pair,
    signature_key_pair
);
#[cfg(feature = "extensions-draft")]
test_optional_reader!(
    corrupted_application_export_tree,
    write_application_export_tree,
    application_export_tree
);
#[cfg(feature = "virtual-clients-draft")]
test_optional_reader!(
    corrupted_vc_derivation_epoch_state,
    write_vc_derivation_epoch_state,
    vc_derivation_epoch_state
);
#[cfg(feature = "virtual-clients-draft")]
test_optional_reader!(
    corrupted_vc_operation_tree,
    write_vc_operation_tree,
    vc_operation_tree
);

#[test]
fn corrupted_list() {
    let storage = MemoryStorage::default();
    let group_id = TestValue(vec![1]);
    let leaf_node = TestValue(vec![2, 3]);

    assert_eq!(
        storage.own_leaf_nodes::<_, TestValue>(&group_id),
        Ok(vec![])
    );
    storage.append_own_leaf_node(&group_id, &leaf_node).unwrap();
    assert_eq!(storage.own_leaf_nodes(&group_id), Ok(vec![leaf_node]));

    for corrupted in CORRUPTED_VALUES {
        // Corrupt the outer list of serialized entities.
        corrupt_only_value(&storage, corrupted);
        assert_eq!(
            storage.own_leaf_nodes::<_, TestValue>(&group_id),
            Err(MemoryStorageError::SerializationError)
        );

        // Keep the outer list valid, but corrupt a serialized entity inside it.
        let list = serde_json::to_vec(&vec![corrupted.to_vec()]).unwrap();
        corrupt_only_value(&storage, &list);
        assert_eq!(
            storage.own_leaf_nodes::<_, TestValue>(&group_id),
            Err(MemoryStorageError::SerializationError)
        );
    }
}

#[test]
fn corrupted_encryption_epoch_key_pairs() {
    let storage = MemoryStorage::default();
    let group_id = TestValue(vec![1]);
    let epoch = TestValue(vec![2]);
    let key_pairs = vec![TestValue(vec![3, 4])];

    assert_eq!(
        storage.encryption_epoch_key_pairs::<_, _, TestValue>(&group_id, &epoch, 0),
        Ok(vec![])
    );
    storage
        .write_encryption_epoch_key_pairs(&group_id, &epoch, 0, &key_pairs)
        .unwrap();
    assert_eq!(
        storage.encryption_epoch_key_pairs(&group_id, &epoch, 0),
        Ok(key_pairs)
    );

    for corrupted in CORRUPTED_VALUES {
        corrupt_only_value(&storage, corrupted);
        assert_eq!(
            storage.encryption_epoch_key_pairs::<_, _, TestValue>(&group_id, &epoch, 0),
            Err(MemoryStorageError::SerializationError)
        );
    }
}

#[cfg(feature = "virtual-clients-draft")]
#[test]
fn corrupted_retained_key_package_material() {
    let storage = MemoryStorage::default();
    let epoch_id = TestValue(vec![1]);
    let key_package_ref = TestValue(vec![2]);
    let material = TestValue(vec![3, 4]);

    assert_eq!(
        storage.retained_key_package_material::<_, TestValue>(&key_package_ref),
        Ok(None)
    );
    storage
        .write_retained_key_package_material_batch(
            &epoch_id,
            &TestValue(vec![5]),
            &[(key_package_ref.clone(), material.clone())],
        )
        .unwrap();
    assert_eq!(
        storage.retained_key_package_material(&key_package_ref),
        Ok(Some(material))
    );

    // Isolate the material from the operation tree and epoch tag in the batch.
    storage
        .values
        .write()
        .unwrap()
        .retain(|key, _| key.starts_with(b"RetainedKeyPackageMaterial"));
    for corrupted in CORRUPTED_VALUES {
        corrupt_only_value(&storage, corrupted);
        assert_eq!(
            storage.retained_key_package_material::<_, TestValue>(&key_package_ref),
            Err(MemoryStorageError::SerializationError)
        );
    }
}
