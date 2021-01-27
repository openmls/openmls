//! Test decryption key index computation in larger trees.
use openmls::prelude::*;

mod utils;

use std::convert::TryFrom;
use test_macros::ctest;
use utils::managed_utils::*;

ctest!(decryption_key_index_computation {
    let ciphersuite_name = CiphersuiteName::try_from(_ciphersuite_code).unwrap();
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();

    // Some basic setup functions for the managed group.
    let handshake_message_format = HandshakeMessageFormat::Plaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = default_callbacks::default_callbacks();
    let managed_group_config =
        ManagedGroupConfig::new(handshake_message_format, update_policy, 10, callbacks);
    let number_of_clients = 20;
    let setup = ManagedTestSetup::new(managed_group_config, number_of_clients);
    setup.create_clients();
        // Create a basic group with more than 4 members to create a tree with intermediate nodes.
        let group_id = setup.create_random_group(10, ciphersuite).unwrap();
        let mut groups = setup.groups.borrow_mut();
        let group = groups.get_mut(&group_id).unwrap();

        // Now we have to create a situation, where the resolution is neither
        // the leaf, nor the common ancestor closest to the root. To do that, we
        // first have the member at index 0 remove the one at index 2, thus
        // populating its own parent node.

        // Find the identity of the member with leaf index 0.
        let (_, remover_id) = &group
            .members
            .iter()
            .find(|(index, _)| index == &0)
            .unwrap()
            .clone();
        setup
            .remove_clients_by_index(ActionType::Commit, group, &remover_id, &[2])
            .unwrap();

        // Then we have the member at index 7 remove the one at index 3. This
        // causes a secret to be encrypted to the parent node of index 0, which
        // fails if the index of the decryption key is computed incorrectly.
        // Find the member with index 0.

        // Find the identity of the member with leaf index 7.
        let (_, remover_id) = &group
            .members
            .iter()
            .find(|(index, _)| index == &7)
            .unwrap()
            .clone();
        setup
            .remove_clients_by_index(ActionType::Commit, group, &remover_id, &[3])
            .unwrap();

        // Since the decryption failure doesn't cause a panic, but only an error
        // message in the callback, we also have to check that the group states
        // match for all group members.
        setup.check_group_states(group);
});
