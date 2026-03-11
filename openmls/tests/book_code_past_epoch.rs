use std::time::{Duration, SystemTime};

use openmls::prelude::*;
use openmls::test_utils::single_group_test_framework::*;
use openmls_test::openmls_test;

#[openmls_test]
fn book_example_past_epoch() {
    // Set up Alice party
    let alice_party = CorePartyState::<Provider>::new("alice");

    // set up the group creation config
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        // XXX: What happens if this is set as well as calling max_past_epochs as well?
        .disable_past_epoch_secret_deletion()
        .ciphersuite(ciphersuite)
        .build();

    // create a group
    let group_id = GroupId::from_slice(b"Test Group");

    let mut group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        mls_group_create_config,
    )
    .expect("error creating group");

    let [alice] = group_state.members_mut(&["alice"]);
    let alice_group = &mut alice.group;

    // delete all past epoch secrets before a timestamp
    alice_group.delete_past_epoch_secrets(PastEpochDeletion::before_timestamp(SystemTime::now()));

    // delete past epoch secrets before a timestamp, leaving the latest three, at most
    alice_group.delete_past_epoch_secrets(
        PastEpochDeletion::before_timestamp(SystemTime::now()).max_past_epochs(3),
    );

    // delete all past epoch secrets older than a duration
    alice_group.delete_past_epoch_secrets(PastEpochDeletion::older_than_duration(
        Duration::from_hours(48),
    ));

    // delete all past epoch secrets older than a duration, leaving the latest three, at most
    alice_group.delete_past_epoch_secrets(
        PastEpochDeletion::older_than_duration(Duration::from_hours(48)).max_past_epochs(3),
    );

    // delete all past epoch secrets
    alice_group.delete_past_epoch_secrets(PastEpochDeletion::delete_all());
}
