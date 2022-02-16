use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    group::MlsGroupConfig,
    test_utils::{
        test_framework::{ActionType, CodecUse, MlsGroupTestSetup},
        *,
    },
    tree::*,
};

/// This test makes sure the filtering of the exclusion list during resolution
/// works as intended.
#[apply(ciphersuites_and_backends)]
fn test_exclusion_list(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Number of nodes in the tree
    const NODES: usize = 31;
    // Resolution for the root node of that tree
    const FULL_RESOLUTION: &[usize] = &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30];
    // Arbitrary exclusion list (leaf indices)
    const EXCLUSION_LIST: &[usize] = &[5, 6, 7, 8, 9, 10, 11];
    // Expected filtered resolution (the nodes from the exclusion list should be
    // stripped from the full resolution)
    const FILTERED_RESOLUTION: &[usize] = &[0, 2, 4, 6, 8, 24, 26, 28, 30];

    // Build a list of nodes, for which we need credentials and key package bundles
    let mut nodes = vec![];
    let mut key_package_bundles = vec![];
    for i in 0..NODES {
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
        if i != NODES - 1 {
            // We insert blank parent nodes to get a longer resolution list
            nodes.push(None);
        }
    }

    // The first key package bundle is used for the tree holder
    let key_package_bundle = key_package_bundles.remove(0);

    let tree = RatchetTree::new_from_nodes(backend, key_package_bundle, &nodes)
        .expect("An unexpected error occurred.");

    let root = treemath::root(LeafIndex::from(NODES / 2));

    // Test full resolution
    let exclusion_list = HashSet::new();
    let full_resolution = tree
        .resolve(root, &exclusion_list)
        .iter()
        .map(|node_index| node_index.as_usize())
        .collect::<Vec<usize>>();

    // We expect to have all resolved nodes
    assert_eq!(FULL_RESOLUTION, full_resolution);

    // Test resolution with exclusion list
    let exclusion_list_node_indexes = EXCLUSION_LIST
        .iter()
        .map(|&index| LeafIndex::from(index))
        .collect::<Vec<LeafIndex>>();
    let exclusion_list = exclusion_list_node_indexes.iter().collect();
    let filtered_resultion = tree
        .resolve(root, &exclusion_list)
        .iter()
        .map(|node_index| node_index.as_usize())
        .collect::<Vec<usize>>();

    // We expect to only see the nodes that were not removed by the filtering
    assert_eq!(FILTERED_RESOLUTION, filtered_resultion);
}

/// Test the `original_child_resolution` function that is used to calculate
/// parent hashes
#[apply(ciphersuites_and_backends)]
fn test_original_child_resolution(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Number of leaf nodes in the tree
    const NODES: usize = 10;
    // Resolution for root left child
    const LEFT_CHILD_RESOLUTION: &[usize] = &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14];
    // Arbitrary unmerged leaves for root
    const ROOT_UNMERGED_LEAVES: &[u32] = &[2, 3, 4];
    // Expected child resolution
    const EXPECTED_CHILD_RESOLUTION: &[usize] = &[0, 1, 2, 3, 5, 7, 9, 10, 11, 12, 13, 14];

    // Build a list of nodes, for which we need credentials and key package bundles
    let mut nodes = vec![];
    let mut key_package_bundles = vec![];
    for i in 0..NODES {
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
        if i != NODES - 1 {
            // We insert blank parent nodes to get a longer resolution list
            nodes.push(None);
        }
    }

    // Root index
    let root_index = treemath::root(LeafIndex::from(NODES));

    // The first key package bundle is used for the tree holder
    let key_package_bundle = key_package_bundles.remove(0);

    let mut tree = RatchetTree::new_from_nodes(backend, key_package_bundle, &nodes)
        .expect("An unexpected error occurred.");

    // Left child index
    let left_child_index = treemath::left(root_index).expect("An unexpected error occurred.");

    // Populate the expected public key list
    let expected_public_keys_full = LEFT_CHILD_RESOLUTION
        .iter()
        .filter(|index| nodes[**index].is_some())
        .map(|index| {
            nodes[*index]
                .as_ref()
                .expect("An unexpected error occurred.")
                .public_hpke_key()
                .expect("An unexpected error occurred.")
        })
        .collect::<Vec<&HpkePublicKey>>();

    // Since the root node has no unmerged leaves, we expect all keys to be returned
    assert_eq!(
        tree.original_child_resolution(left_child_index),
        expected_public_keys_full
    );

    // Add unmerged leaves to root node
    let public_key = backend
        .crypto()
        .derive_hpke_keypair(
            ciphersuite.hpke_config(),
            Secret::random(ciphersuite, backend, None)
                .expect("Not enough randomness.")
                .as_slice(),
        )
        .public
        .into();
    let new_root_node = Node {
        node_type: NodeType::Parent,
        node: Some(ParentNode {
            parent_hash: vec![].into(),
            public_key,
            unmerged_leaves: ROOT_UNMERGED_LEAVES
                .iter()
                .map(|index| LeafIndex::from(*index))
                .collect(),
        }),
        key_package: None,
    };
    tree.nodes[root_index] = new_root_node;

    // Populate the expected public key list
    let expected_public_keys_filtered = EXPECTED_CHILD_RESOLUTION
        .iter()
        .filter(|index| nodes[**index].is_some())
        .map(|index| {
            nodes[*index]
                .as_ref()
                .expect("An unexpected error occurred.")
                .public_hpke_key()
                .expect("An unexpected error occurred.")
        })
        .collect::<Vec<&HpkePublicKey>>();

    // Since the root node now has unmerged leaves, we expect only certain public
    // keys to be returned
    assert_eq!(
        tree.original_child_resolution(left_child_index),
        expected_public_keys_filtered
    );
}

/// Test if unmerged leaves are properly excluded when computing the parent hash
/// of a parent node higher up in the tree.
#[test]
fn test_exclusion_for_parent_nodes() {
    // Create a large tree members.
    let mls_group_config = MlsGroupConfig::test_default();

    // We need 16 clients, such that we can create a group with 16 members. 16
    // members means that we have two layers between the root and the leaves.
    let number_of_clients = 16;
    let setup = MlsGroupTestSetup::new(
        mls_group_config,
        number_of_clients,
        CodecUse::SerializedMessages,
    );

    let group_id = setup
        .create_group(Ciphersuite::default())
        .expect("An unexpected error occurred.");

    let mut groups = setup.groups.borrow_mut();
    let group = groups
        .get_mut(&group_id)
        .expect("An unexpected error occurred.");

    let (_, group_creator_id) = group
        .members
        .first()
        .expect("An unexpected error occurred.")
        .clone();

    // We add 16 - 2 = 14 members such that we have a group of 15. We add the
    // last member manually later.
    let addees = setup
        .random_new_members_for_group(group, number_of_clients - 2)
        .expect("An unexpected error occurred.");

    // Have one client add all the other clients, such that only the direct path
    // of the group creator is non-blank.
    setup
        .add_clients(ActionType::Commit, group, &group_creator_id, addees)
        .expect("An unexpected error occurred.");

    // Now we have two clients in the right tree half do an update. This is such
    // that the right child of the root has two children that are full nodes. It
    // is important that the member beneath the left child of the right child of
    // the root updates second. This is so that the left child has the parent
    // hash of the right child of the root.
    let (_, updater_id) = group.members[12].clone();

    setup
        .self_update(ActionType::Commit, group, &updater_id, None)
        .expect("An unexpected error occurred.");

    let (_, updater_id) = group.members[8].clone();

    setup
        .self_update(ActionType::Commit, group, &updater_id, None)
        .expect("An unexpected error occurred.");

    // Now we add the final group member, which should lead to an unmerged leaf
    // being added to the right child of the right child of the root, thus
    // invalidating the parent hash of the left child of the right child of the
    // root if the exclusion list is not applied to parent nodes.
    let (_, group_creator_id) = group
        .members
        .first()
        .expect("An unexpected error occurred.")
        .clone();

    let addees = setup
        .random_new_members_for_group(group, 1)
        .expect("An unexpected error occurred.");

    // We now add a new client to the group. Upon receiving the new message, the
    // client will check the parent hash of all nodes in the tree as mandated by
    // the spec and thus notice an invalid parent hash of the right child of the
    // root. If there is an error, it will be bubbled up by the test framework,
    // triggering the `expect` and thus failing the test.
    setup
        .add_clients(ActionType::Commit, group, &group_creator_id, addees)
        .expect("Error when adding new client to group.")
}
