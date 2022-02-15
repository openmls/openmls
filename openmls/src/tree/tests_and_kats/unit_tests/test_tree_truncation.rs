use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    ciphersuite::Ciphersuite,
    credentials::{CredentialBundle, CredentialType},
    group::MlsGroupConfig,
    key_packages::{KeyPackageBundle, LeafIndex},
    test_utils::{
        test_framework::{ActionType, CodecUse, MlsGroupTestSetup},
        *,
    },
    tree::node::{Node, NodeType},
    tree::RatchetTree,
};

#[apply(backends)]
fn test_trim(backend: &impl OpenMlsCryptoProvider) {
    // Build a list of nodes, for which we need credentials and key package bundles
    let mut nodes = vec![];
    let mut key_package_bundles = vec![];
    let ciphersuite = Ciphersuite::default();
    let tree_sizes = vec![5, 15, 21, 65];
    for number_of_leaves in tree_sizes {
        println!("number of leaves: {:?}", number_of_leaves);
        for i in 0..number_of_leaves {
            let credential_bundle = CredentialBundle::new(
                vec![i as u8],
                CredentialType::Basic,
                ciphersuite.signature_algorithm(),
                backend,
            )
            .expect("An unexpected error occurred.");
            let key_package_bundle =
                KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, vec![])
                    .expect("An unexpected error occurred.");

            // We build a leaf node from the key packages
            let leaf_node = Node {
                node_type: NodeType::Leaf,
                key_package: Some(key_package_bundle.key_package().clone()),
                node: None,
            };
            key_package_bundles.push(key_package_bundle);
            nodes.push(Some(leaf_node));
            // We skip the last parent node (trees should always end with a leaf node)
            if i != number_of_leaves - 1 {
                nodes.push(None);
            }
        }

        // Extend the nodes with a blank leaf and corresponding blank parent node.
        nodes.extend_from_slice(&[None, None]);
        println!("final number of nodes: {:?}", nodes.len());

        let key_package_bundle = key_package_bundles.remove(0);
        let mut tree = RatchetTree::new_from_nodes(backend, key_package_bundle, &nodes)
            .expect("An unexpected error occurred.");

        let size_untrimmed = tree.tree_size();
        println!("size untrimmed: {:?}", size_untrimmed);

        tree.trim_tree();

        // The trim should have removed the last node and parent.
        assert_eq!(size_untrimmed.as_usize(), tree.tree_size().as_usize() + 2);

        // Now that there are no blanks in the end, the size shouldn't change when trimming.

        // Let's make a leaf blank that's not in the end just to be sure.
        tree.blank_member(LeafIndex::from(2u32));

        let size_untrimmed = tree.tree_size();

        tree.trim_tree();

        assert_eq!(size_untrimmed, tree.tree_size());
    }
}

#[test]
fn test_truncation_after_removal() {
    // Set up a group with 8 members.
    let mls_group_config = MlsGroupConfig::test_default();
    let test_group_sizes = vec![5, 15, 21, 65];
    for number_of_clients in test_group_sizes {
        let setup = MlsGroupTestSetup::new(
            mls_group_config.clone(),
            number_of_clients,
            CodecUse::SerializedMessages,
        );

        let group_id = setup
            .create_random_group(number_of_clients, Ciphersuite::default())
            .expect("An unexpected error occurred.");

        let mut groups = setup.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("An unexpected error occurred.");

        // Get the id of the member at index 0
        let (_, remover_id) = group
            .members
            .iter()
            .find(|(index, _)| *index == 0)
            .expect("An unexpected error occurred.")
            .clone();

        // Remove the rightmost 2 members in the tree
        setup
            .remove_clients_by_index(
                ActionType::Commit,
                group,
                &remover_id,
                &[number_of_clients - 2, number_of_clients - 1],
            )
            .expect("error while removing members from group");

        // Test if the tree was truncated. The tree's size should be ((number of
        // members) * 2) - 1, i.e. 11 with 6 members.
        assert_eq!(group.public_tree.len(), (number_of_clients - 2) * 2 - 1)
    }
}

#[test]
fn test_truncation_after_update() {
    // Set up a group with 8 members.
    let mls_group_config = MlsGroupConfig::test_default();
    let test_group_sizes = vec![5, 15, 21, 65];
    for number_of_clients in test_group_sizes {
        let setup = MlsGroupTestSetup::new(
            mls_group_config.clone(),
            number_of_clients,
            CodecUse::SerializedMessages,
        );

        let group_id = setup
            .create_random_group(number_of_clients, Ciphersuite::default())
            .expect("An unexpected error occurred.");

        let mut groups = setup.groups.borrow_mut();
        let group = groups
            .get_mut(&group_id)
            .expect("An unexpected error occurred.");

        // Get the id of the member at index 0
        let (_, updater_id) = group
            .members
            .iter()
            .find(|(index, _)| *index == 0)
            .expect("An unexpected error occurred.")
            .clone();

        // Remove the rightmost 2 members in the tree
        setup
            .self_update(ActionType::Commit, group, &updater_id, None)
            .expect("error while doing self-update");

        // Test if the tree was truncated. The tree's size should be ((number of
        // members) * 2) - 1, i.e. 15 with 8 members.
        assert_eq!(group.public_tree.len(), number_of_clients * 2 - 1)
    }
}
