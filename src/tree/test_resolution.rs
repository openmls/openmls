use super::*;

/// This test makes sure the filtering of the exclusion list during resolution
/// works as intended.
#[test]

fn test_exclusion_list() {
    for ciphersuite in Config::supported_ciphersuites() {
        // Number of nodes in the tree
        const NODES: usize = 31;
        // Resolution for the root node of that tree
        const FULL_RESOLUTION: &[usize] =
            &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30];
        // Arbitrary exclusion list
        const EXCLUSION_LIST: &[usize] = &[10, 12, 14, 16, 18, 20, 22];
        // Expected filtered resolution (the nodes from the exclusion list should be
        // stripped from the full resolution)
        const FILTERED_RESOLUTION: &[usize] = &[0, 2, 4, 6, 8, 24, 26, 28, 30];

        // Build a list of nodes, for which we need credentials and key package bundles
        let mut nodes = vec![];
        let mut key_package_bundles = vec![];
        for i in 0..NODES {
            let credential_bundle =
                CredentialBundle::new(vec![i as u8], CredentialType::Basic, ciphersuite.name())
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
            if i != NODES - 1 {
                // We insert blank parent nodes to get a longer resolution list
                nodes.push(None);
            }
        }

        // The first key package bundle is used for the tree holder
        let key_package_bundle = key_package_bundles.remove(0);

        let tree = RatchetTree::new_from_nodes(&ciphersuite, key_package_bundle, &nodes).unwrap();

        let root = treemath::root(NodeIndex::from(NODES).into()).unwrap();

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
            .map(|index| NodeIndex::from(*index))
            .collect::<Vec<NodeIndex>>();
        let exclusion_list = HashSet::from_iter(exclusion_list_node_indexes.iter());
        let filtered_resultion = tree
            .resolve(root, &exclusion_list)
            .iter()
            .map(|node_index| node_index.as_usize())
            .collect::<Vec<usize>>();

        // We expect to only see the nodes that were not removed by the filtering
        assert_eq!(FILTERED_RESOLUTION, filtered_resultion);
    }
}
