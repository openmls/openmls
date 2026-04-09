//! This module contains tests regarding the use of [`MessageSecretsStore`]
//!
//! Tests for `MlsGroup::delete_past_epoch_secrets()`
//! - `max_epochs_policy_with_duration()`
//!     - test deletion using a duration, when the group keeps at most `n` past epoch secret
//!       entries by default
//! - `max_epochs_policy_with_timestamp()`
//!     - test deletion using a timestamp, when the group keeps at most `n` past epoch secret
//!       entries by default
//! - `keep_all_policy_with_duration()`
//!     - test deletion using a duration, when the group keeps all past epoch
//!       secrets by default
//! - `keep_all_policy_with_timestamp()`
//!     - test deletion using a timestamp, when the group keeps all past epoch
//!       secrets by default
//! - `delete_all()`:
//!     - test deletion of past epoch secrets using `PastEpochDeletion::delete_all()`
//!
//! Additional tests for the message secrets store:
//! - `test_secret_tree_store()`
//! - `test_empty_secret_tree_store()`

use openmls_traits::signatures::Signer;

use crate::{
    binary_tree::LeafNodeIndex,
    group::past_secrets::MessageSecretsStore,
    prelude::{tests_and_kats::utils::generate_credential_with_key, *},
    schedule::message_secrets::MessageSecrets,
};
use std::time::Duration;

const INTERVAL: Duration = Duration::from_millis(100);

/// Helper function to set up an MlsGroup configured with the provided past epoch deletion policy
fn setup<Provider: OpenMlsProvider + Default>(
    ciphersuite: Ciphersuite,
    policy: PastEpochDeletionPolicy,
) -> (Provider, impl Signer, MlsGroup) {
    let alice_provider = Provider::default();
    let alice_credential_with_keys = generate_credential_with_key(
        b"Alice".to_vec(),
        ciphersuite.signature_algorithm(),
        &alice_provider,
    );
    let alice_signer = alice_credential_with_keys.signer;
    // Define the MlsGroup configuration
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .set_past_epoch_deletion_policy(policy)
        .ciphersuite(ciphersuite)
        .build();

    // === Alice creates a group ===
    let alice_group = MlsGroup::new(
        &alice_provider,
        &alice_signer,
        &mls_group_create_config,
        alice_credential_with_keys.credential_with_key.clone(),
    )
    .expect("An unexpected error occurred.");

    (alice_provider, alice_signer, alice_group)
}

/// Helper function for applying and merging commits, as part of testing past epoch deletion
/// This function also ensures that the number of past epoch trees available is what is expected
fn apply_and_merge_commits<Provider: OpenMlsProvider>(
    num_commits: usize,
    provider: &Provider,
    signer: &impl Signer,
    group: &mut MlsGroup,
    policy: PastEpochDeletionPolicy,
) {
    for _ in 0..num_commits {
        // create and stage sample commit
        // for simplicity, this is a commit that updates the GroupContextExtensions
        group
            .update_group_context_extensions(provider, Extensions::empty(), signer)
            .expect("error building commit");
        group
            .merge_pending_commit(provider)
            .expect("error merging commit");

        if let PastEpochDeletionPolicy::MaxEpochs(epochs) = policy {
            // assert nothing was deleted yet, and that the number of
            // past epoch secrets is the number of all past epoch secrets
            assert!(group.message_secrets_store().num_past_epoch_trees() <= epochs);
        } else {
            // assert nothing was deleted yet, and that the number of
            // past epoch secrets is the number of all past epoch secrets
            assert_eq!(
                group.message_secrets_store().num_past_epoch_trees(),
                group.epoch().as_u64() as usize
            );
        }
    }
}

/// This test checks the case where:
/// - max_past_epochs = 2, and time-based cleanup using a duration
#[openmls_test::openmls_test]
fn max_epochs_with_duration<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) {
    let policy = PastEpochDeletionPolicy::MaxEpochs(2);
    // set up a provider, signer and group
    let (alice_provider, alice_signer, mut alice_group) =
        setup::<Provider>(ciphersuite, policy.clone());

    let start = std::time::Instant::now();

    // apply and merge commits to advance the group epoch
    apply_and_merge_commits(4, &alice_provider, &alice_signer, &mut alice_group, policy);

    // sleep for INTERVAL + elapsed time, to ensure all secrets will be removed
    std::thread::sleep(INTERVAL + start.elapsed());
    // manually delete all before INTERVAL (early)
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::older_than_duration(INTERVAL),
        )
        .expect("error deleting past epoch secrets");

    // assert all past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );

    // load from storage to check persistence
    let alice_group_stored = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
        .expect("error loading group")
        .expect("no group for id");
    assert_eq!(
        alice_group_stored
            .message_secrets_store()
            .num_past_epoch_trees(),
        0
    );
}

/// This test checks the case where:
/// - max_past_epochs = 2, and time-based cleanup using a timestamp
#[openmls_test::openmls_test]
fn max_epochs_policy_with_timestamp<Provider: crate::storage::OpenMlsProvider>() {
    let policy = PastEpochDeletionPolicy::MaxEpochs(2);
    // set up a provider, signer and group
    let (alice_provider, alice_signer, mut alice_group) =
        setup::<Provider>(ciphersuite, policy.clone());

    // === Test the `delete_past_epoch_secrets()` API with a timestamp ===

    let start = std::time::SystemTime::now();

    // apply and merge commits to advance the group epoch
    apply_and_merge_commits(4, &alice_provider, &alice_signer, &mut alice_group, policy);

    // manually delete all before start, leaving at most 3 entries
    // NOTE: all entries were inserted after `start`
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::before_timestamp(start).max_past_epochs(3),
        )
        .expect("error deleting past epoch secrets");
    // assert no past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        2
    );

    // manually delete all before start, leaving at most 1 entry
    // NOTE: all entries were inserted after `start`
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::before_timestamp(start).max_past_epochs(1),
        )
        .expect("error deleting past epoch secrets");
    // assert one past secret was kept
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        1
    );

    // manually delete all before SystemTime::now()
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::before_timestamp(std::time::SystemTime::now()),
        )
        .expect("error deleting past epoch secrets");
    // assert all past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );

    // load from storage to check persistence
    let alice_group_stored = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
        .expect("error loading group")
        .expect("no group for id");
    assert_eq!(
        alice_group_stored
            .message_secrets_store()
            .num_past_epoch_trees(),
        0
    );
}

/// This test checks the case where:
/// - epoch deletion policy: KeepAll, and time-based cleanup with duration
#[openmls_test::openmls_test]
fn keep_all_policy_with_duration<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) {
    let policy = PastEpochDeletionPolicy::KeepAll;
    // set up a provider, signer and group
    let (alice_provider, alice_signer, mut alice_group) =
        setup::<Provider>(ciphersuite, policy.clone());

    let start = std::time::Instant::now();

    // apply and merge commits to advance the group epoch
    apply_and_merge_commits(4, &alice_provider, &alice_signer, &mut alice_group, policy);

    // sleep for INTERVAL + elapsed time`
    std::thread::sleep(INTERVAL + start.elapsed());

    // manually delete all before
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::older_than_duration(INTERVAL),
        )
        .expect("error deleting past epoch secrets");
    // assert all past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );

    // load from storage to check persistence
    let alice_group_stored = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
        .expect("error loading group")
        .expect("no group for id");
    assert_eq!(
        alice_group_stored
            .message_secrets_store()
            .num_past_epoch_trees(),
        0
    );
}

/// This test checks the case where:
/// - epoch deletion policy: KeepAll, and time-based cleanup with timestamp
#[openmls_test::openmls_test]
fn keep_all_policy_with_timestamp<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
) {
    let policy = PastEpochDeletionPolicy::KeepAll;

    // set up a provider, signer and group
    let (alice_provider, alice_signer, mut alice_group) =
        setup::<Provider>(ciphersuite, policy.clone());

    // apply and merge commits to advance the group epoch
    apply_and_merge_commits(4, &alice_provider, &alice_signer, &mut alice_group, policy);

    // manually delete all before UNIX_EPOCH, leaving at most 5 entries
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::before_timestamp(std::time::SystemTime::UNIX_EPOCH)
                .max_past_epochs(5),
        )
        .expect("error deleting past epoch secrets");
    // assert no past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        4
    );

    // manually delete all before UNIX_EPOCH, leaving at most 3 entries
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::before_timestamp(std::time::SystemTime::UNIX_EPOCH)
                .max_past_epochs(3),
        )
        .expect("error deleting past epoch secrets");
    // assert no past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        3
    );

    // manually delete all before UNIX_EPOCH, leaving at most 1 entry
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::before_timestamp(std::time::SystemTime::UNIX_EPOCH)
                .max_past_epochs(1),
        )
        .expect("error deleting past epoch secrets");
    // assert one past secret was kept
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        1
    );

    // manually delete all before SystemTime::now()
    alice_group
        .delete_past_epoch_secrets(
            &alice_provider,
            PastEpochDeletion::before_timestamp(std::time::SystemTime::now()),
        )
        .expect("error deleting past epoch secrets");
    // assert all past secrets deleted
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );

    // load from storage to check persistence
    let alice_group_stored = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
        .expect("error loading group")
        .expect("no group for id");
    assert_eq!(
        alice_group_stored
            .message_secrets_store()
            .num_past_epoch_trees(),
        0
    );
}

/// This test checks the manual cleanup of all past epoch secrets.
#[openmls_test::openmls_test]
fn delete_all<Provider: crate::storage::OpenMlsProvider>() {
    // test several policies
    for policy in [
        PastEpochDeletionPolicy::KeepAll,
        PastEpochDeletionPolicy::MaxEpochs(2),
        PastEpochDeletionPolicy::MaxEpochs(0),
    ] {
        // set up a provider, signer and group
        let (alice_provider, alice_signer, mut alice_group) =
            setup::<Provider>(ciphersuite, policy.clone());

        // apply and merge commits to advance the group epoch
        apply_and_merge_commits(4, &alice_provider, &alice_signer, &mut alice_group, policy);

        // manually delete all before start, leaving at most 3 entries
        // NOTE: all entries were inserted after `start`
        alice_group
            .delete_past_epoch_secrets(&alice_provider, PastEpochDeletion::delete_all())
            .expect("error deleting past epoch secrets");
        // assert all past secrets deleted
        assert_eq!(
            alice_group.message_secrets_store().num_past_epoch_trees(),
            0
        );
        // load from storage to check persistence
        let alice_group_stored = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
            .expect("error loading group")
            .expect("no group for id");
        assert_eq!(
            alice_group_stored
                .message_secrets_store()
                .num_past_epoch_trees(),
            0
        );
    }
}

/// Helper function to create a message secrets store with mixed
/// `Some` and `None` timestamp entries
fn setup_tree_store_with_timestamps<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    provider: &Provider,
    entries: &[Option<std::time::SystemTime>],
) -> MessageSecretsStore {
    // Create a store
    let mut message_secrets_store = MessageSecretsStore::new_with_secret(
        &PastEpochDeletionPolicy::KeepAll,
        MessageSecrets::random(ciphersuite, provider.rand(), LeafNodeIndex::new(0)),
    );

    // Populate with past epoch trees
    // use the index as the epoch
    for (epoch, timestamp) in entries.iter().enumerate() {
        let message_secrets = MessageSecrets::random(
            ciphersuite,
            provider.rand(),
            LeafNodeIndex::new(epoch as u32),
        );

        let message_secrets = match timestamp {
            Some(timestamp) => message_secrets.with_timestamp(*timestamp),
            None => message_secrets.without_timestamp(),
        };

        message_secrets_store.add_past_epoch_tree(epoch as u64, message_secrets, Vec::new());
    }

    message_secrets_store
}

/// Test persistence of an update to the past epoch deletion policy.
#[openmls_test::openmls_test]
fn test_update_policy_persistence<Provider: OpenMlsProvider>(ciphersuite: Ciphersuite) {
    // initial policy
    let initial_policy = PastEpochDeletionPolicy::MaxEpochs(3);
    // set up a provider, signer and group
    let (alice_provider, _alice_signer, mut alice_group) =
        setup::<Provider>(ciphersuite, initial_policy.clone());

    // load group from storage
    let alice_group_stored = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
        .expect("error loading group")
        .expect("no group for id");
    // check policy
    assert_eq!(
        alice_group_stored.past_epoch_deletion_policy(),
        &initial_policy
    );

    for new_policy in [
        PastEpochDeletionPolicy::KeepAll,
        PastEpochDeletionPolicy::MaxEpochs(3),
        PastEpochDeletionPolicy::MaxEpochs(2),
    ] {
        alice_group
            .set_past_epoch_deletion_policy(&alice_provider, new_policy.clone())
            .unwrap();
        // load group from storage
        let alice_group_stored = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
            .expect("error loading group")
            .expect("no group for id");
        // check policy
        assert_eq!(alice_group_stored.past_epoch_deletion_policy(), &new_policy);
    }
}

/// Test changing the past epoch deletion policy on a group.
#[openmls_test::openmls_test]
fn test_update_policy<Provider: OpenMlsProvider>(ciphersuite: Ciphersuite) {
    // initial policy
    let policy = PastEpochDeletionPolicy::MaxEpochs(3);
    // set up a provider, signer and group
    let (alice_provider, alice_signer, mut alice_group) =
        setup::<Provider>(ciphersuite, policy.clone());

    // apply and merge commits to advance the group epoch
    apply_and_merge_commits(4, &alice_provider, &alice_signer, &mut alice_group, policy);
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        3
    );

    // update the policy
    let new_policy = PastEpochDeletionPolicy::MaxEpochs(5);
    alice_group
        .set_past_epoch_deletion_policy(&alice_provider, new_policy.clone())
        .expect("error updating policy");

    // apply and merge additional commits to advance the group epoch
    for _ in 0..10 {
        alice_group
            .update_group_context_extensions(&alice_provider, Extensions::empty(), &alice_signer)
            .expect("error building commit");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("error merging commit");
    }
    // check that the policy was updated on the group
    assert_eq!(alice_group.past_epoch_deletion_policy(), &new_policy);
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        5
    );

    // update the policy
    let new_policy = PastEpochDeletionPolicy::MaxEpochs(2);
    alice_group
        .set_past_epoch_deletion_policy(&alice_provider, new_policy.clone())
        .expect("error updating policy");
    // check that the policy was updated on the group
    assert_eq!(alice_group.past_epoch_deletion_policy(), &new_policy);
    // check that the store was resized correctly
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        2
    );

    // update the policy
    let new_policy = PastEpochDeletionPolicy::KeepAll;
    alice_group
        .set_past_epoch_deletion_policy(&alice_provider, new_policy.clone())
        .expect("error updating policy");

    // apply and merge additional commits to advance the group epoch
    for _ in 0..8 {
        alice_group
            .update_group_context_extensions(&alice_provider, Extensions::empty(), &alice_signer)
            .expect("error building commit");
        alice_group
            .merge_pending_commit(&alice_provider)
            .expect("error merging commit");
    }
    // check that the policy was updated on the group
    assert_eq!(alice_group.past_epoch_deletion_policy(), &new_policy);
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        10
    );

    // delete all past epoch secrets
    alice_group
        .delete_past_epoch_secrets(&alice_provider, PastEpochDeletion::delete_all())
        .expect("error deleting past epoch secrets");
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        0
    );

    // apply and merge an additional commit to advance the group epoch
    alice_group
        .update_group_context_extensions(&alice_provider, Extensions::empty(), &alice_signer)
        .expect("error building commit");
    alice_group
        .merge_pending_commit(&alice_provider)
        .expect("error merging commit");
    // NOTE: now, the number of past epoch secrets is less than the maximum
    // configured by the policy that will be applied next.
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        1
    );

    // update the policy
    let new_policy = PastEpochDeletionPolicy::MaxEpochs(2);
    alice_group
        .set_past_epoch_deletion_policy(&alice_provider, new_policy.clone())
        .expect("error updating policy");
    // check that the store was resized correctly
    assert_eq!(
        alice_group.message_secrets_store().num_past_epoch_trees(),
        1
    );

    // load from storage to check persistence
    let alice_group_stored = MlsGroup::load(alice_provider.storage(), alice_group.group_id())
        .expect("error loading group")
        .expect("no group for id");
    assert_eq!(
        alice_group_stored
            .message_secrets_store()
            .num_past_epoch_trees(),
        1
    );
    assert_eq!(alice_group_stored.past_epoch_deletion_policy(), &new_policy);
}

/// Test a secret tree store with all legacy timestamps, where a timestamp is available for the
/// current MessageSecrets
#[openmls_test::openmls_test]
fn test_secret_tree_store_migration_next_epoch_timestamp() {
    let provider = &Provider::default();

    // Set up a secret tree store with mixed Some and None timestamps
    // NOTE: For completeness, this sequence of epoch tree timestamps is tested.
    // In practice, Some and None timestamps should not occur in this pattern.
    let mut message_secrets_store = setup_tree_store_with_timestamps(
        ciphersuite,
        provider,
        &[
            None, //0
            None, //1
        ],
    );

    // test deletion of all message secrets before the timestamp
    message_secrets_store.delete_past_epoch_secrets(PastEpochDeletion::before_timestamp(
        std::time::SystemTime::UNIX_EPOCH,
    ));
    assert_eq!(message_secrets_store.num_past_epoch_trees(), 2);

    // test deletion of all message secrets before the timestamp
    message_secrets_store.delete_past_epoch_secrets(PastEpochDeletion::before_timestamp(
        std::time::SystemTime::now(),
    ));
    assert_eq!(message_secrets_store.num_past_epoch_trees(), 0);
}

/// Test a secret tree store with all legacy timestamps, where a timestamp is available for the
/// current MessageSecrets
#[openmls_test::openmls_test]
fn test_secret_tree_store_migration_next_epoch_duration() {
    let provider = &Provider::default();

    // Set up a secret tree store with mixed Some and None timestamps
    // NOTE: For completeness, this sequence of epoch tree timestamps is tested.
    // In practice, Some and None timestamps should not occur in this pattern.
    let mut message_secrets_store = setup_tree_store_with_timestamps(
        ciphersuite,
        provider,
        &[
            None, //0
            None, //1
        ],
    );

    // test deletion of all message secrets before a longer duration
    message_secrets_store.delete_past_epoch_secrets(PastEpochDeletion::older_than_duration(
        Duration::from_hours(2),
    ));
    assert_eq!(message_secrets_store.num_past_epoch_trees(), 2);

    // test deletion of all message secrets before the timestamp
    message_secrets_store.delete_past_epoch_secrets(PastEpochDeletion::older_than_duration(
        Duration::from_nanos(0),
    ));
    assert_eq!(message_secrets_store.num_past_epoch_trees(), 0);
}

/// Test a secret tree store with a mix of legacy and current timestamps,
/// deleting by a provided timestamp
#[openmls_test::openmls_test]
fn test_secret_tree_store_mixed_delete_by_timestamp() {
    let provider = &Provider::default();

    let timestamp_before = std::time::SystemTime::now();

    // Set up a secret tree store with mixed Some and None timestamps
    // NOTE: For completeness, this sequence of epoch tree timestamps is tested.
    // In practice, Some and None timestamps should not occur in this pattern.
    let mut message_secrets_store = setup_tree_store_with_timestamps(
        ciphersuite,
        provider,
        &[
            None,                                    //0
            Some(std::time::SystemTime::UNIX_EPOCH), //1
            None,                                    //2
            Some(std::time::SystemTime::UNIX_EPOCH), //3
            None,                                    //4
            Some(std::time::SystemTime::now()),      //5
            None,                                    //6
        ],
    );

    // test deletion of all message secrets before the timestamp
    message_secrets_store
        .delete_past_epoch_secrets(PastEpochDeletion::before_timestamp(timestamp_before));

    // ensure that the past epoch secrets are now empty
    // assert all past secrets deleted
    // NOTE: the `None` tree at the end will not be deleted
    assert_eq!(message_secrets_store.num_past_epoch_trees(), 3);
    assert!(message_secrets_store.secrets_for_epoch(4).is_some());
    assert!(message_secrets_store.secrets_for_epoch(5).is_some());
    assert!(message_secrets_store.secrets_for_epoch(6).is_some());
}

/// Test a secret tree store with a mix of legacy and current timestamps
/// deleting by a provided duration
#[openmls_test::openmls_test]
fn test_secret_tree_store_mixed_delete_by_duration() {
    let provider = &Provider::default();

    // Set up a secret tree store with mixed Some and None timestamps
    // NOTE: For completeness, this sequence of epoch tree timestamps is tested.
    // In practice, Some and None timestamps should not occur in this pattern.
    let mut message_secrets_store = setup_tree_store_with_timestamps(
        ciphersuite,
        provider,
        &[
            None,                                    //0
            Some(std::time::SystemTime::UNIX_EPOCH), //1
            None,                                    //2
            Some(std::time::SystemTime::UNIX_EPOCH), //3
            None,                                    //4
            Some(std::time::SystemTime::now()),      //5
            None,                                    //6
        ],
    );

    // test deletion of all message secrets before `now()`
    message_secrets_store.delete_past_epoch_secrets(PastEpochDeletion::older_than_duration(
        Duration::from_hours(3),
    ));

    // ensure that the past epoch secrets are now empty
    // assert all past secrets deleted
    // NOTE: the `None` tree at epoch 3 will not be deleted
    assert_eq!(message_secrets_store.num_past_epoch_trees(), 3);
    assert!(message_secrets_store.secrets_for_epoch(4).is_some());
    assert!(message_secrets_store.secrets_for_epoch(5).is_some());
    assert!(message_secrets_store.secrets_for_epoch(6).is_some());
}

/// Basic test for the message secrets store
#[openmls_test::openmls_test]
fn test_secret_tree_store() {
    let provider = &Provider::default();
    // Create a store that keeps up to 3 epochs
    let mut message_secrets_store = MessageSecretsStore::new_with_secret(
        &PastEpochDeletionPolicy::MaxEpochs(3),
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
        &PastEpochDeletionPolicy::MaxEpochs(0),
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
