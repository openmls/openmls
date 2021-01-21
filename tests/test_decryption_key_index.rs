use openmls::prelude::*;

mod utils;

use utils::managed_utils::*;

#[test]
fn test_decryption_key_index_computation() {
    // Some basic setup functions for the managed group.
    let handshake_message_format = HandshakeMessageFormat::Plaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = default_callbacks::default_callbacks();
    let managed_group_config =
        ManagedGroupConfig::new(handshake_message_format, update_policy, callbacks);
    let number_of_clients = 20;
    let setup = ManagedTestSetup::new(managed_group_config, number_of_clients);
    setup.create_clients();

    for ciphersuite in Config::supported_ciphersuites() {
        // Create a basic group with more than 4 members to create a tree with intermediate nodes.
        let group_id = setup.create_random_group(10, ciphersuite).unwrap();
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        // Now we have to create a situation, where the resolution is neither
        // the leaf, nor the common ancestor closest to the root. To do that, we
        // first have the member at index 0 remove the one at index 2, thus
        // populating its own parent node.
        let (_, remover_id) = &group.members[0].clone();
        let (_, target_id) = &group.members[2].clone();
        setup
            .remove_clients(
                ActionType::Commit,
                group,
                &remover_id,
                vec![target_id.clone()],
            )
            .unwrap();

        // Then we have the member at index 7 (it's just index 6 in the member
        // list) remove the one at index 3 (index 2 at the member list). This
        // causes a secret to be encrypted to the parent node of index 0, which
        // fails if the index of the decryption key is computed incorrectly.
        let (_, remover_id) = &group.members[6].clone();
        let (_, target_id) = &group.members[2].clone();
        setup
            .remove_clients(
                ActionType::Commit,
                group,
                &remover_id,
                vec![target_id.clone()],
            )
            .unwrap();

        // Since the decryption failure doesn't cause a panic, but only an error
        // message in the callback, we also have to check that the group states
        // match for all group members.
        setup.check_group_states(group);
    }
}
