//! This module contains tests regarding the use of [`MessageSecretsStore`]

use crate::{
    binary_tree::LeafNodeIndex, group::past_secrets::MessageSecretsStore,
    schedule::message_secrets::MessageSecrets, test_utils::*,
};

#[openmls_test::openmls_test]
fn test_secret_tree_store() {
    // Create a store that keeps up to 3 epochs
    let mut message_secrets_store = MessageSecretsStore::new_with_secret(
        3,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0)),
    );

    // Add message secrets to the store
    message_secrets_store.add(
        0,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0)),
        Vec::new(),
    );

    // Make sure we can access the message secrets we just stored
    assert!(message_secrets_store.secrets_for_epoch_mut(0).is_some());

    // Add 5 more message secrets, this should drop trees from earlier epochs
    for i in 1..6u64 {
        message_secrets_store.add(
            i,
            MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0)),
            Vec::new(),
        );
    }

    // These epochs should be in the store
    assert!(message_secrets_store.secrets_for_epoch_mut(3).is_some());
    assert!(message_secrets_store.secrets_for_epoch_mut(4).is_some());
    assert!(message_secrets_store.secrets_for_epoch_mut(5).is_some());

    // These epochs should not be in the store
    assert!(message_secrets_store.secrets_for_epoch_mut(0).is_none());
    assert!(message_secrets_store.secrets_for_epoch_mut(1).is_none());
    assert!(message_secrets_store.secrets_for_epoch_mut(2).is_none());
    assert!(message_secrets_store.secrets_for_epoch_mut(6).is_none());
}

#[openmls_test::openmls_test]
fn test_empty_secret_tree_store() {
    // Create a store that keeps no epochs
    let mut message_secrets_store = MessageSecretsStore::new_with_secret(
        0,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0)),
    );

    // Add message secrets to the store
    message_secrets_store.add(
        0,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0)),
        Vec::new(),
    );

    // Make sure we cannot access the message secrets we just stored
    assert!(message_secrets_store.secrets_for_epoch_mut(0).is_none());
}
