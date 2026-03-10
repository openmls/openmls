use openmls::prelude::*;
use openmls::test_utils::single_group_test_framework::*;
use openmls_test::openmls_test;

#[openmls_test]
fn book_example_past_epoch() {
    // Set up Alice party
    let alice_party = CorePartyState::<Provider>::new("alice");

    // set up the group creation config
    let mls_group_create_config = MlsGroupCreateConfig::builder()
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
    alice_group.delete_past_epoch_secrets_before(std::time::SystemTime::now(), None);

    // delete past epoch secrets before a timestamp, leaving the latest three, at most
    alice_group.delete_past_epoch_secrets_before(std::time::SystemTime::now(), Some(3));

    // delete all past epoch secrets older than a duration
    alice_group.delete_past_epoch_secrets_older_than(std::time::Duration::from_hours(48), None);

    // delete all past epoch secrets older than a duration, leaving the latest three, at most
    alice_group.delete_past_epoch_secrets_older_than(std::time::Duration::from_hours(48), Some(3));

    // delete all past epoch secrets
    alice_group.delete_past_epoch_secrets(None);

    // delete all past epoch secrets, leaving the latest three, at least
    alice_group.delete_past_epoch_secrets(Some(3));
}
