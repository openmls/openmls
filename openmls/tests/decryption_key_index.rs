//! Test decryption key index computation in larger trees.
use openmls::{
    prelude::*,
    test_utils::test_framework::{
        noop_authentication_service, ActionType, CodecUse, MlsGroupTestSetup,
    },
};
use openmls_test::openmls_test;

#[openmls_test]
fn decryption_key_index_computation() {
    println!("Testing ciphersuite {ciphersuite:?}");

    // Some basic setup functions for the MlsGroup.
    let mls_group_create_config = MlsGroupCreateConfig::test_default(ciphersuite);
    let number_of_clients = 20;
    let setup = MlsGroupTestSetup::<Provider>::new(
        mls_group_create_config,
        number_of_clients,
        CodecUse::StructMessages,
    );

    // Create a basic group with more than 4 members to create a tree with intermediate nodes.
    let group_id = setup
        .create_random_group(10, ciphersuite, noop_authentication_service)
        .expect("An unexpected error occurred.");
    let mut groups = setup.groups.write().expect("An unexpected error occurred.");
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    // Now we have to create a situation, where the resolution is neither
    // the leaf, nor the common ancestor closest to the root. To do that, we
    // first have the member at index 0 remove the one at index 2, thus
    // populating its own parent node.

    // Find the identity of the member with leaf index 0.
    let (_, remover_id) = &group
        .members()
        .find(|(index, _)| index == &0)
        .expect("An unexpected error occurred.");
    setup
        .remove_clients(
            ActionType::Commit,
            group,
            remover_id,
            &[LeafNodeIndex::new(2)],
            noop_authentication_service,
        )
        .expect("An unexpected error occurred.");

    // Then we have the member at index 7 remove the one at index 3. This
    // causes a secret to be encrypted to the parent node of index 0, which
    // fails if the index of the decryption key is computed incorrectly.
    // Find the member with index 0.

    // Find the identity of the member with leaf index 7.
    let (_, remover_id) = &group
        .members()
        .find(|(index, _)| index == &7)
        .expect("An unexpected error occurred.");
    setup
        .remove_clients(
            ActionType::Commit,
            group,
            remover_id,
            &[LeafNodeIndex::new(3)],
            noop_authentication_service,
        )
        .expect("An unexpected error occurred.");

    // Since the decryption failure doesn't cause a panic, but only an error
    // message in the callback, we also have to check that the group states
    // match for all group members.
    setup.check_group_states(group, noop_authentication_service);
}
