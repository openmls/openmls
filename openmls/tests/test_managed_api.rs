use openmls::{
    prelude::*,
    test_utils::test_framework::{ActionType, CodecUse, MlsGroupTestSetup},
    test_utils::*,
    *,
};

#[apply(ciphersuites)]
fn test_mls_group_api(ciphersuite: Ciphersuite) {
    // Some basic setup functions for the MlsGroup.
    let mls_group_config = MlsGroupConfig::test_default(ciphersuite);
    let number_of_clients = 20;
    let setup = MlsGroupTestSetup::new(
        mls_group_config,
        number_of_clients,
        CodecUse::SerializedMessages,
    );

    let group_id = setup
        .create_random_group(3, ciphersuite)
        .expect("An unexpected error occurred.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    // Add two new members.
    let (_, adder_id) = group.members().next().unwrap();
    let new_members = setup
        .random_new_members_for_group(group, 2)
        .expect("An unexpected error occurred.");
    setup
        .add_clients(ActionType::Commit, group, &adder_id, new_members)
        .expect("An unexpected error occurred.");

    // Remove a member
    let (_, remover_id) = group.members().nth(2).unwrap();
    let (target_index, _) = group.members().nth(3).unwrap();
    setup
        .remove_clients(
            ActionType::Commit,
            group,
            &remover_id,
            &[LeafNodeIndex::new(target_index)],
        )
        .expect("An unexpected error occurred.");

    // Check that all group members agree on the same group state.
    setup.check_group_states(group);
}
