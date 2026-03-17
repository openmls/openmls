use std::time::{Duration, SystemTime};

use openmls::prelude::*;
use openmls::test_utils::single_group_test_framework::*;
use openmls_test::openmls_test;

#[openmls_test]
fn book_example_past_epoch() {
    // ---------- Example with `KeepAll` ----------

    // create a group id
    let group_id = GroupId::from_slice(b"Test Group");

    // Set up Alice party
    let alice_party = CorePartyState::<Provider>::new("alice");
    let provider = &alice_party.provider;

    // set up the group creation config
    // ANCHOR: config_keep_all
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::KeepAll)
        .ciphersuite(ciphersuite)
        .build();
    // ANCHOR_END: config_keep_all

    let mut group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        mls_group_create_config,
    )
    .expect("error creating group");

    let [alice] = group_state.members_mut(&["alice"]);
    let mls_group = &mut alice.group;

    let timestamp = SystemTime::now();

    // ANCHOR: timestamp
    // delete all past epoch secrets before a timestamp
    mls_group
        .delete_past_epoch_secrets(provider, PastEpochDeletion::before_timestamp(timestamp))
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: timestamp

    // ANCHOR: timestamp_with_max_epochs
    // delete past epoch secrets before a timestamp, leaving the latest three, at most
    mls_group
        .delete_past_epoch_secrets(
            provider,
            PastEpochDeletion::before_timestamp(timestamp).max_past_epochs(3),
        )
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: timestamp_with_max_epochs

    // ANCHOR: duration
    // delete all past epoch secrets older than a duration
    mls_group
        .delete_past_epoch_secrets(
            provider,
            PastEpochDeletion::older_than_duration(Duration::from_hours(48)),
        )
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: duration

    // ANCHOR: duration_with_max_epochs
    // delete all past epoch secrets older than a duration, leaving the latest three, at most
    mls_group
        .delete_past_epoch_secrets(
            provider,
            PastEpochDeletion::older_than_duration(Duration::from_hours(48)).max_past_epochs(3),
        )
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: duration_with_max_epochs

    // ANCHOR: delete_all
    // delete all past epoch secrets
    mls_group
        .delete_past_epoch_secrets(provider, PastEpochDeletion::delete_all())
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: delete_all

    // ANCHOR: delete_all_past_secrets_with_none_timestamps
    // delete all past epoch secrets without timestamps
    mls_group
        .delete_past_epoch_secrets(provider, PastEpochDeletion::delete_all_without_timestamps())
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: delete_all_past_secrets_with_none_timestamps

    // ---------- Additional example of group creation with `MaxEpochs(3)` ----------

    // create a group id
    let group_id = GroupId::from_slice(b"Additional test group");

    // ANCHOR: config_max_epochs
    // set up the group creation config
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        // keep at most 3 past epoch secrets
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(3))
        .ciphersuite(ciphersuite)
        .build();
    // ANCHOR_END: config_max_epochs

    let mut group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        mls_group_create_config,
    )
    .expect("error creating group");

    let [alice] = group_state.members_mut(&["alice"]);
    let mls_group = &mut alice.group;
    // ANCHOR: set_policy_on_existing_group
    // keep all past epoch secrets by default
    mls_group
        .set_past_epoch_deletion_policy(provider, PastEpochDeletionPolicy::KeepAll)
        .expect("error setting past epoch deletion policy");

    // keep a maximum of 3 past epoch secrets
    mls_group
        .set_past_epoch_deletion_policy(provider, PastEpochDeletionPolicy::MaxEpochs(3))
        .expect("error setting past epoch deletion policy");
    // ANCHOR_END: set_policy_on_existing_group
}
