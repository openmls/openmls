use super::*;

#[test]

fn test_exclusion_list() {
    for ciphersuite in Config::supported_ciphersuites() {
        const NODES: usize = 31;
        const FULL_RESOLUTION: &[usize] =
            &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 22, 24, 26, 28, 30];
        const EXCLUSION_LIST: &[usize] = &[10, 12, 14, 16, 18, 20, 22];
        const FILTERED_RESOLUTION: &[usize] = &[0, 2, 4, 6, 8, 24, 26, 28, 30];

        let mut nodes = vec![];
        let mut key_package_bundles = vec![];
        for i in 0..NODES {
            let credential_bundle =
                CredentialBundle::new(vec![i as u8], CredentialType::Basic, ciphersuite.name())
                    .unwrap();
            let key_package_bundle =
                KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, vec![]).unwrap();

            let leaf_node = Node {
                node_type: NodeType::Leaf,
                key_package: Some(key_package_bundle.key_package().clone()),
                node: None,
            };
            key_package_bundles.push(key_package_bundle);
            nodes.push(Some(leaf_node));
            if i != NODES - 1 {
                nodes.push(None);
            }
        }

        let key_package_bundle = key_package_bundles.remove(0);
        drop(key_package_bundles);

        let tree = RatchetTree::new_from_nodes(&ciphersuite, key_package_bundle, &nodes).unwrap();

        let root = treemath::root(NodeIndex::from(NODES).into());

        // Test full resolution
        let exclusion_list = HashSet::new();
        let full_resolution = tree
            .resolve(root, &exclusion_list)
            .iter()
            .map(|node_index| node_index.as_usize())
            .collect::<Vec<usize>>();

        assert_eq!(FULL_RESOLUTION, full_resolution);

        // Test resolution with exclusion list
        let exclusion_list = HashSet::from_iter(
            EXCLUSION_LIST
                .iter()
                .map(|index| NodeIndex::from(*index))
                .collect::<Vec<NodeIndex>>(),
        );
        let filtered_resultion = tree
            .resolve(root, &exclusion_list)
            .iter()
            .map(|node_index| node_index.as_usize())
            .collect::<Vec<usize>>();

        assert_eq!(FILTERED_RESOLUTION, filtered_resultion);
    }
}
