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
    let group = &mut alice.group;

    let timestamp = SystemTime::now();

    // delete all past epoch secrets before a timestamp
    // ANCHOR: timestamp
    group
        .delete_past_epoch_secrets(provider, PastEpochDeletion::before_timestamp(timestamp))
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: timestamp

    // delete past epoch secrets before a timestamp, leaving the latest three, at most
    // ANCHOR: timestamp_with_max_epochs
    group
        .delete_past_epoch_secrets(
            provider,
            PastEpochDeletion::before_timestamp(timestamp).max_past_epochs(3),
        )
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: timestamp_with_max_epochs

    // delete all past epoch secrets older than a duration
    // ANCHOR: duration
    group
        .delete_past_epoch_secrets(
            provider,
            PastEpochDeletion::older_than_duration(Duration::from_hours(48)),
        )
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: duration

    // delete all past epoch secrets older than a duration, leaving the latest three, at most
    // ANCHOR: duration_with_max_epochs
    group
        .delete_past_epoch_secrets(
            provider,
            PastEpochDeletion::older_than_duration(Duration::from_hours(48)).max_past_epochs(3),
        )
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: duration_with_max_epochs

    // delete all past epoch secrets
    // ANCHOR: delete_all
    group
        .delete_past_epoch_secrets(provider, PastEpochDeletion::delete_all())
        .expect("error deleting past epoch secrets");
    // ANCHOR_END: delete_all

    // ---------- Additional example of group creation with `MaxEpochs(3)` ----------

    // create a group id
    let group_id = GroupId::from_slice(b"Additional test group");

    // set up the group creation config
    // ANCHOR: config_max_epochs
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .set_past_epoch_deletion_policy(PastEpochDeletionPolicy::MaxEpochs(3))
        .ciphersuite(ciphersuite)
        .build();
    // ANCHOR_END: config_max_epochs

    let _group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        mls_group_create_config,
    )
    .expect("error creating group");
}
