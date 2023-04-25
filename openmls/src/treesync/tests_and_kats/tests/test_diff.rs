use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use rstest::*;
use rstest_reuse::apply;

use crate::{
    group::GroupId,
    key_packages::KeyPackageBundle,
    test_utils::credential,
    treesync::{node::Node, RatchetTree, TreeSync},
};

// Verifies that when we add a leaf to a tree with blank leaf nodes, the leaf will be added at the leftmost free leaf index
#[apply(ciphersuites_and_backends)]
fn test_free_leaf_computation(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let credential_0 = credential(b"leaf0", ciphersuite.signature_algorithm(), backend);
    let kpb_0 = KeyPackageBundle::new(backend, &credential_0, ciphersuite, &credential_0);

    let credential_3 = credential(b"leaf3", ciphersuite.signature_algorithm(), backend);
    let kpb_3 = KeyPackageBundle::new(backend, &credential_3, ciphersuite, &credential_3);

    // Build a rudimentary tree with two populated and two empty leaf nodes.
    let ratchet_tree = RatchetTree::trimmed(vec![
        Some(Node::LeafNode(kpb_0.key_package().leaf_node().clone())), // Leaf 0
        None,
        None, // Leaf 1
        None,
        None, // Leaf 2
        None,
        Some(Node::LeafNode(kpb_3.key_package().leaf_node().clone())), // Leaf 3
    ]);

    // Get the encryption key pair from the leaf.
    let tree = TreeSync::from_ratchet_tree(backend, ciphersuite, ratchet_tree)
        .expect("error generating tree");

    // Create and add a new leaf. It should go to leaf index 1

    let credential_2 = credential(b"leaf2", ciphersuite.signature_algorithm(), backend);
    let kpb_2 = KeyPackageBundle::new(backend, &credential_2, ciphersuite, &credential_2);

    let mut diff = tree.empty_diff();
    let free_leaf_index = diff.free_leaf_index();
    let added_leaf_index = diff
        .add_leaf(kpb_2.key_package().leaf_node().clone())
        .expect("error adding leaf");
    assert_eq!(free_leaf_index.u32(), 1u32);
    assert_eq!(free_leaf_index, added_leaf_index);

    let free_leaf_index = diff.free_leaf_index();

    assert_eq!(free_leaf_index.u32(), 2u32);
}
