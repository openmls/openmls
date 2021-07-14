use crate::{
    ciphersuite::Ciphersuite,
    credentials::{CredentialBundle, CredentialType},
    group::{HandshakeMessageFormat, ManagedGroupCallbacks, ManagedGroupConfig, UpdatePolicy},
    node::{Node, NodeType},
    prelude::{KeyPackageBundle, LeafIndex},
    test_utils::test_framework::{ActionType, ManagedTestSetup},
    tree::RatchetTree,
};

#[test]
fn test_trim() {
    // Build a list of nodes, for which we need credentials and key package bundles
    let mut nodes = vec![];
    let mut key_package_bundles = vec![];
    let ciphersuite = Ciphersuite::default();
    for i in 0..10 {
        let credential_bundle = CredentialBundle::new(
            vec![i as u8],
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, vec![]).unwrap();

        // We build a leaf node from the key packages
        let leaf_node = Node {
            node_type: NodeType::Leaf,
            key_package: Some(key_package_bundle.key_package().clone()),
            node: None,
        };
        key_package_bundles.push(key_package_bundle);
        nodes.push(Some(leaf_node));
        // We skip the last parent node (trees should always end with a leaf node)
        if i != 9 {
            nodes.push(None);
        }
    }

    // Extend the nodes with a blank leaf and corresponding blank parent node.
    nodes.extend_from_slice(&[None, None]);

    let key_package_bundle = key_package_bundles.remove(0);
    let mut tree = RatchetTree::new_from_nodes(key_package_bundle, &nodes).unwrap();

    let size_untrimmed = tree.tree_size();

    tree.trim_tree();

    // The trim should have removed the last node and parent.
    assert_eq!(size_untrimmed.as_usize(), tree.tree_size().as_usize() + 2);

    // Now that there are no blanks in the end, the size shouldn't change when trimming.

    // Let's make a leaf in the middle blank just to be sure.
    tree.blank_member(LeafIndex::from(4u32));

    let size_untrimmed = tree.tree_size();

    tree.trim_tree();

    assert_eq!(size_untrimmed, tree.tree_size());
}

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

#[test]
fn test_truncation_after_update() {
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
    let (_, updater_id) = group
        .members
        .iter()
        .find(|(index, _)| *index == 0)
        .unwrap()
        .clone();

    // Remove the rightmost 2 members in the tree
    setup
        .self_update(ActionType::Commit, group, &updater_id, None)
        .expect("error while doing self-update");

    // Test if the tree was truncated. The tree's size should be ((number of
    // members) * 2) - 1, i.e. 15 with 8 members.
    assert_eq!(group.public_tree.len(), 15)
}
