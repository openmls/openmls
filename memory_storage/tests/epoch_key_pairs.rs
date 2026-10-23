//! Regression tests for the epoch key pair storage key encoding.
//!
//! `epoch_key_pairs_id` builds the storage key by concatenating the serialized
//! group id, epoch and leaf index. All three are variable length, so without a
//! delimiter or a length prefix distinct tuples can serialize to the same key.
//! For example `epoch = 1, leaf_index = 23` and `epoch = 12, leaf_index = 3`
//! both produce `{"value":[...]}123`. That makes one write overwrite the other
//! and a read return the wrong epoch's key pairs. See issue #2264.

use openmls_memory_storage::MemoryStorage;
use openmls_traits::storage::{traits, Entity, Key, StorageProvider, CURRENT_VERSION};
use serde::{Deserialize, Serialize};

/// Mirrors the serialization of the real `GroupId`, which wraps a `VLBytes` and
/// serializes to `{"value":[..]}`.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestGroupId {
    value: Vec<u8>,
}
impl traits::GroupId<CURRENT_VERSION> for TestGroupId {}
impl Key<CURRENT_VERSION> for TestGroupId {}

/// Mirrors the serialization of the real `GroupEpoch`, a newtype over `u64`
/// that serializes to a bare integer.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestEpochKey(u64);
impl traits::EpochKey<CURRENT_VERSION> for TestEpochKey {}
impl Key<CURRENT_VERSION> for TestEpochKey {}

#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
struct TestHpkeKeyPair(Vec<u8>);
impl Entity<CURRENT_VERSION> for TestHpkeKeyPair {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for TestHpkeKeyPair {}

/// Two distinct `(epoch, leaf_index)` tuples whose naive concatenation collides
/// must not share a storage key: writing one must not overwrite or shadow the
/// other.
#[test]
fn epoch_key_pairs_do_not_collide() {
    let group_id = TestGroupId {
        value: vec![0xab, 0xcd],
    };
    let storage = MemoryStorage::default();

    // (epoch = 1, leaf_index = 23) and (epoch = 12, leaf_index = 3) both encode
    // to the concatenation `{"value":[171,205]}123` on the buggy encoding.
    let first = vec![TestHpkeKeyPair(b"epoch-1-leaf-23".to_vec())];
    let second = vec![TestHpkeKeyPair(b"epoch-12-leaf-3".to_vec())];

    storage
        .write_encryption_epoch_key_pairs(&group_id, &TestEpochKey(1), 23, &first)
        .unwrap();
    storage
        .write_encryption_epoch_key_pairs(&group_id, &TestEpochKey(12), 3, &second)
        .unwrap();

    let first_read: Vec<TestHpkeKeyPair> = storage
        .encryption_epoch_key_pairs(&group_id, &TestEpochKey(1), 23)
        .unwrap();
    let second_read: Vec<TestHpkeKeyPair> = storage
        .encryption_epoch_key_pairs(&group_id, &TestEpochKey(12), 3)
        .unwrap();

    assert_eq!(
        first, first_read,
        "epoch 1 / leaf 23 must still hold its own key pairs"
    );
    assert_eq!(
        second, second_read,
        "epoch 12 / leaf 3 must still hold its own key pairs"
    );
}

/// Deleting one `(epoch, leaf_index)` entry must not delete a distinct entry
/// that happens to share the same naive concatenation.
#[test]
fn epoch_key_pairs_delete_does_not_collide() {
    let group_id = TestGroupId {
        value: vec![0xab, 0xcd],
    };
    let storage = MemoryStorage::default();

    let first = vec![TestHpkeKeyPair(b"epoch-1-leaf-23".to_vec())];
    let second = vec![TestHpkeKeyPair(b"epoch-12-leaf-3".to_vec())];

    storage
        .write_encryption_epoch_key_pairs(&group_id, &TestEpochKey(1), 23, &first)
        .unwrap();
    storage
        .write_encryption_epoch_key_pairs(&group_id, &TestEpochKey(12), 3, &second)
        .unwrap();

    storage
        .delete_encryption_epoch_key_pairs(&group_id, &TestEpochKey(1), 23)
        .unwrap();

    let first_read: Vec<TestHpkeKeyPair> = storage
        .encryption_epoch_key_pairs(&group_id, &TestEpochKey(1), 23)
        .unwrap();
    let second_read: Vec<TestHpkeKeyPair> = storage
        .encryption_epoch_key_pairs(&group_id, &TestEpochKey(12), 3)
        .unwrap();

    assert!(first_read.is_empty(), "the deleted entry must be gone");
    assert_eq!(
        second, second_read,
        "deleting a colliding tuple must not remove an unrelated entry"
    );
}

/// Distinct group ids with colliding naive encodings must stay separate.
#[test]
fn epoch_key_pairs_distinct_members_do_not_collide() {
    let storage = MemoryStorage::default();

    // Two different members of the same group, far enough apart in epoch that
    // the digit strings interleave under naive concatenation.
    let member_a = TestGroupId { value: vec![0x01] };
    let member_b = TestGroupId {
        value: vec![0x01, 0x23],
    };

    let a = vec![TestHpkeKeyPair(b"member-a".to_vec())];
    let b = vec![TestHpkeKeyPair(b"member-b".to_vec())];

    storage
        .write_encryption_epoch_key_pairs(&member_a, &TestEpochKey(1), 23, &a)
        .unwrap();
    storage
        .write_encryption_epoch_key_pairs(&member_b, &TestEpochKey(12), 3, &b)
        .unwrap();

    let a_read: Vec<TestHpkeKeyPair> = storage
        .encryption_epoch_key_pairs(&member_a, &TestEpochKey(1), 23)
        .unwrap();
    let b_read: Vec<TestHpkeKeyPair> = storage
        .encryption_epoch_key_pairs(&member_b, &TestEpochKey(12), 3)
        .unwrap();

    assert_eq!(a, a_read, "member A's entry must be intact");
    assert_eq!(b, b_read, "member B's entry must be intact");
}
