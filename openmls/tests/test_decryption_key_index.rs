//! Test decryption key index computation in larger trees.
use openmls::{
    prelude::*,
    test_utils::{
        test_framework::{ActionType, CodecUse, ManagedTestSetup},
        OpenMlsTestRand,
    },
};
use rust_crypto::RustCrypto;

#[macro_use]
mod utils;

ctest_ciphersuites!(decryption_key_index_computation, test(ciphersuite_name: CiphersuiteName) {
    let mut rng = OpenMlsTestRand::new();
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();
    let crypto = RustCrypto::default();

    // Some basic setup functions for the managed group.
    let handshake_message_format = WireFormat::MlsPlaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config =
        ManagedGroupConfig::new(handshake_message_format, update_policy, 10, 0, false, callbacks);
    let number_of_clients = 20;
    let setup = ManagedTestSetup::new(managed_group_config, number_of_clients, CodecUse::StructMessages, &mut rng, &crypto);
    // Create a basic group with more than 4 members to create a tree with intermediate nodes.
    let group_id = setup.create_random_group(10, ciphersuite, &mut rng, &crypto).unwrap();
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
        .remove_clients_by_index(ActionType::Commit, group, remover_id, &[2], &mut rng, &crypto)
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
        .remove_clients_by_index(ActionType::Commit, group, remover_id, &[3], &mut rng, &crypto)
        .unwrap();

    // Since the decryption failure doesn't cause a panic, but only an error
    // message in the callback, we also have to check that the group states
    // match for all group members.
    setup.check_group_states(&crypto, group, &mut rng);
});
