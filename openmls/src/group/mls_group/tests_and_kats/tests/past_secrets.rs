//! This module contains tests regarding the use of [`MessageSecretsStore`]
//!
//! Tests:
//! - case where max_past_epochs = 2, with time-limited cleanup:
//!     - test_past_secrets_epoch_deletion_limited_with_time
//! - case where max_past_epochs = isize::MAX, with time-limited cleanup:
//!     - test_past_secrets_epoch_deletion_time_no_limit
//!
//! At the end, some basic tests for the message secrets store are also included.

use crate::{
    binary_tree::LeafNodeIndex,
    group::past_secrets::MessageSecretsStore,
    prelude::{tests_and_kats::utils::generate_credential_with_key, *},
    schedule::message_secrets::MessageSecrets,
};
use std::time::Duration;

/// This test checks the case where:
/// - max_past_epochs = 2, and time-limited cleanup
#[openmls_test::openmls_test]
fn test_past_secrets_epoch_deletion_limited_with_time<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) {
    // long enough that creating and applying commits below is completed
    const INTERVAL: Duration = Duration::from_millis(100);

    let alice_provider = &mut Provider::default();
    let alice_credential_with_keys = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let alice_signer = &alice_credential_with_keys.signer;
    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .max_past_epochs(2)
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        alice_provider,
        alice_signer,
        &mls_group_create_config,
        alice_credential_with_keys.credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Test the `delete_epoch_secrets_older_than()` API ===

    let start = std::time::Instant::now();
    for _ in 0..4 {
        // create and stage sample commit
        // for simplicity, this is a commit that updates the GroupContextExtensions
        alice_group
            .update_group_context_extensions(alice_provider, Extensions::empty(), alice_signer)
            .expect("error building commit");
        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging commit");
        // manually delete all before INTERVAL (early)
        //alice_group.delete_epoch_secrets_older_than(INTERVAL, None);
        // assert nothing was deleted yet, and that the number of
        // past epoch secrets is
        assert!(alice_group.message_secrets_store().num_past_epoch_trees() <= 2);
    }

    // sleep for INTERVAL + elapsed time, to ensure all secrets will be removed
    std::thread::sleep(INTERVAL + start.elapsed());
    // manually delete all before INTERVAL (early)
    alice_group.delete_epoch_secrets_older_than(INTERVAL, None);
    // assert all past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );

    // === Test the `delete_epoch_secrets_before()` API ===

    let start = std::time::SystemTime::now();
    for _ in 0..4 {
        // create and stage sample commit
        // for simplicity, this is a commit that updates the GroupContextExtensions
        alice_group
            .update_group_context_extensions(alice_provider, Extensions::empty(), alice_signer)
            .expect("error building commit");
        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging commit");
        // assert nothing was deleted yet, and that the number of
        // past epoch secrets is the number of all past epoch secrets
        assert!(alice_group.message_secrets_store().num_past_epoch_trees() <= 2);
    }

    // manually delete all before start, leaving at most 3 entries
    // NOTE: all entries were inserted after `start`
    alice_group.delete_epoch_secrets_before(start, 3);
    // assert no past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        2
    );

    // manually delete all before start, leaving at most 1 entry
    // NOTE: all entries were inserted after `start`
    alice_group.delete_epoch_secrets_before(start, 1);
    // assert one past secret was kept
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        1
    );

    // manually delete all before SystemTime::now()
    alice_group.delete_epoch_secrets_before(std::time::SystemTime::now(), None);
    // assert all past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );
}

/// This test checks the case where:
/// - max_past_epochs = isize::MAX, and time-limited cleanup
#[openmls_test::openmls_test]
fn test_past_secrets_epoch_deletion_time_no_limit<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) {
    // long enough that creating and applying commits below is completed
    const INTERVAL: Duration = Duration::from_millis(100);

    let alice_provider = &mut Provider::default();
    let alice_credential_with_keys = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let alice_signer = &alice_credential_with_keys.signer;
    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .max_past_epochs(isize::MAX as usize)
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::new(
        alice_provider,
        alice_signer,
        &mls_group_create_config,
        alice_credential_with_keys.credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    // === Test the `delete_epoch_secrets_older_than()` API ===

    let start = std::time::Instant::now();
    for _ in 0..4 {
        // create and stage sample commit
        // for simplicity, this is a commit that updates the GroupContextExtensions
        alice_group
            .update_group_context_extensions(alice_provider, Extensions::empty(), alice_signer)
            .expect("error building commit");
        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging commit");
        // assert nothing was deleted yet, and that the number of
        // past epoch secrets is the number of all past epoch secrets
        assert_eq!(
            alice_group.message_secrets_store().num_past_epoch_trees(),
            alice_group.epoch().as_u64() as usize
        );
    }

    // sleep for INTERVAL + elapsed time, to ensure all secrets will be removed
    std::thread::sleep(INTERVAL + start.elapsed());
    // manually delete all before INTERVAL (early)
    alice_group.delete_epoch_secrets_older_than(INTERVAL, None);
    // assert all past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );

    // === Test the `delete_epoch_secrets_before()` API ===

    for n in 0..4 {
        // create and stage sample commit
        // for simplicity, this is a commit that updates the GroupContextExtensions
        alice_group
            .update_group_context_extensions(alice_provider, Extensions::empty(), alice_signer)
            .expect("error building commit");
        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging commit");
        // assert nothing was deleted yet, and that the number of
        // past epoch secrets is the number of all past epoch secrets
        assert_eq!(
            alice_group.message_secrets_store().num_past_epoch_trees(),
            n + 1
        );
    }

    // manually delete all before UNIX_EPOCH, leaving at most 5 entries
    alice_group.delete_epoch_secrets_before(std::time::SystemTime::UNIX_EPOCH, 5);
    // assert no past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        4
    );

    // manually delete all before UNIX_EPOCH, leaving at most 3 entries
    alice_group.delete_epoch_secrets_before(std::time::SystemTime::UNIX_EPOCH, 3);
    // assert no past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        3
    );

    // manually delete all before UNIX_EPOCH, leaving at most 1 entry
    alice_group.delete_epoch_secrets_before(std::time::SystemTime::UNIX_EPOCH, 1);
    // assert one past secret was kept
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        1
    );

    // manually delete all before SystemTime::now()
    alice_group.delete_epoch_secrets_before(std::time::SystemTime::now(), None);
    // assert all past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );
}

/// Basic test for the message secrets store
#[openmls_test::openmls_test]
fn test_secret_tree_store() {
    let provider = &Provider::default();
    // Create a store that keeps up to 3 epochs
    let mut message_secrets_store = MessageSecretsStore::new_with_secret(
        3,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0)),
    );

    // Add message secrets to the store
    message_secrets_store.add_past_epoch_tree(
        0,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0))
            .with_timestamp(std::time::SystemTime::now()),
        Vec::new(),
    );

    // Make sure we can access the message secrets we just stored
    assert!(message_secrets_store.secrets_for_epoch_mut(0).is_some());

    // Add 5 more message secrets, this should drop trees from earlier epochs
    for i in 1..6u64 {
        message_secrets_store.add_past_epoch_tree(
            i,
            MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0))
                .with_timestamp(std::time::SystemTime::now()),
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
    let provider = &Provider::default();
    // Create a store that keeps no epochs
    let mut message_secrets_store = MessageSecretsStore::new_with_secret(
        0,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0)),
    );

    // Add message secrets to the store
    message_secrets_store.add_past_epoch_tree(
        0,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0))
            .with_timestamp(std::time::SystemTime::now()),
        Vec::new(),
    );

    // Make sure we cannot access the message secrets we just stored
    assert!(message_secrets_store.secrets_for_epoch_mut(0).is_none());
}
