use crate::{
    ciphersuite::Ciphersuite,
    group::{HandshakeMessageFormat, ManagedGroupCallbacks, ManagedGroupConfig, UpdatePolicy},
    test_utils::test_framework::{ActionType, ManagedTestSetup},
};

#[test]
fn test_truncation_after_removal() {
    // Set up a group with 8 members.
    let handshake_message_format = HandshakeMessageFormat::Plaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config = ManagedGroupConfig::new(
        handshake_message_format,
        update_policy,
        0,
        0,
        true, // use_ratchet_tree_extension
        callbacks,
    );
    let setup = ManagedTestSetup::new(managed_group_config, 8);

    let group_id = setup
        .create_random_group(8, Ciphersuite::default())
        .unwrap();

    let mut groups = setup.groups.borrow_mut();
    let group = groups.get_mut(&group_id).unwrap();

    // Get the id of the member at index 0
    let (_, remover_id) = group
        .members
        .iter()
        .find(|(index, _)| *index == 0)
        .unwrap()
        .clone();

    // Remove the rightmost 2 members in the tree
    setup
        .remove_clients_by_index(ActionType::Commit, group, &remover_id, &[6, 7])
        .expect("error while removing members from group");

    // Test if the tree was truncated. The tree's size should be ((number of
    // members) * 2) - 1, i.e. 11 with 6 members.
    assert_eq!(group.public_tree.len(), 11)
}
