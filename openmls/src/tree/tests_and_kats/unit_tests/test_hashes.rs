use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::tree::*;

#[test]
fn test_parent_hash() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        // Number of leaf nodes in the tree
        const NODES: usize = 31;

        // Build a list of nodes, for which we need credentials and key package bundles
        let mut nodes = vec![];
        let mut key_package_bundles = vec![];
        for i in 0..NODES {
            let credential_bundle = CredentialBundle::new(
                vec![i as u8],
                CredentialType::Basic,
                ciphersuite.signature_scheme(),
                &crypto,
            )
            .expect("An unexpected error occurred.");
            let key_package_bundle =
                KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, &crypto, vec![])
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

        let mut tree = RatchetTree::new_from_nodes(&crypto, key_package_bundle, &nodes)
            .expect("An unexpected error occurred.");

        assert!(tree.verify_parent_hashes(&crypto).is_ok());

        // Populate the parent nodes with fake values
        for index in 0..tree.tree_size().as_usize() {
            // Filter out leaf nodes
            if NodeIndex::from(index).is_parent() {
                let public_key = crypto
                    .crypto()
                    .derive_hpke_keypair(
                        ciphersuite.hpke_config(),
                        Secret::random(ciphersuite, &crypto, None)
                            .expect("Not enough randomness.")
                            .as_slice(),
                    )
                    .public
                    .into();
                let parent_node = ParentNode::new(public_key, &[], &[]);
                let node = Node {
                    key_package: None,
                    node: Some(parent_node),
                    node_type: NodeType::Parent,
                };
                tree.nodes[index] = node;
            }
        }

        // Compute the recursive parent_hash for the first member
        let original_parent_hash = tree.set_parent_hashes(&crypto, LeafIndex::from(0usize));

        // Swap two leaf nodes in the left & right part of the tree
        tree.nodes.swap(15, 47);

        // Compute the parent hash again to verify it has changed
        let leaf_swap_parent_hash = tree.set_parent_hashes(&crypto, LeafIndex::from(0usize));

        assert!(leaf_swap_parent_hash != original_parent_hash);
    }
}
