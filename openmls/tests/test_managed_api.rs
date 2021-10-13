use openmls::{
    prelude::*,
    test_utils::test_framework::{ActionType, CodecUse, ManagedTestSetup},
};

mod utils;

#[test]
fn test_managed_api() {
    // Some basic setup functions for the managed group.
    let handshake_message_format = WireFormat::MlsPlaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config = ManagedGroupConfig::new(
        handshake_message_format,
        update_policy,
        0,
        0,
        false, // use_ratchet_tree_extension
        callbacks,
    );
    let number_of_clients = 20;
    let setup = ManagedTestSetup::new(
        managed_group_config,
        number_of_clients,
        CodecUse::SerializedMessages,
    );

    for ciphersuite in Config::supported_ciphersuites() {
        let group_id = setup.create_random_group(3, ciphersuite).unwrap();
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        // Add two new members.
        let (_, adder_id) = group.members[0].clone();
        let new_members = setup.random_new_members_for_group(group, 2).unwrap();
        setup
            .add_clients(ActionType::Commit, group, &adder_id, new_members)
            .unwrap();

        // Remove a member
        let (_, remover_id) = group.members[2].clone();
        let (_, target_id) = group.members[3].clone();
        setup
            .remove_clients(ActionType::Commit, group, &remover_id, vec![target_id])
            .unwrap();

        // Check that all group members agree on the same group state.
        setup.check_group_states(group);
    }
}
