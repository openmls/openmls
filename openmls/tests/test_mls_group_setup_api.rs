use openmls::{
    prelude::*,
    test_utils::test_framework::{ActionType, CodecUse, MlsGroupTestSetup},
    test_utils::*,
    *,
};

mod utils;

#[apply(ciphersuites)]
fn mls_group_setup_api(ciphersuite: &'static Ciphersuite) {
    // Some basic setup functions for the MlsGroup.
    let mls_group_config = MlsGroupConfig::builder()
        .wire_format(WireFormat::MlsPlaintext)
        .build();
    let number_of_clients = 20;
    let setup = MlsGroupTestSetup::new(
        mls_group_config,
        number_of_clients,
        CodecUse::SerializedMessages,
    );

    let group_id = setup
        .create_random_group(3, ciphersuite)
        .expect("An unexpected error occurred.");
    let mut groups = setup.groups.borrow_mut();
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    // Add two new members.
    let (_, adder_id) = group.members[0].clone();
    let new_members = setup
        .random_new_members_for_group(group, 2)
        .expect("An unexpected error occurred.");
    setup
        .add_clients(ActionType::Commit, group, &adder_id, new_members)
        .expect("An unexpected error occurred.");

    // Remove a member
    let (_, remover_id) = group.members[2].clone();
    let (_, target_id) = group.members[3].clone();
    setup
        .remove_clients(ActionType::Commit, group, &remover_id, vec![target_id])
        .expect("An unexpected error occurred.");

    // Check that all group members agree on the same group state.
    setup.check_group_states(group);
}
