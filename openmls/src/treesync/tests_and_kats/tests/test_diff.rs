use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
use rstest::*;
use rstest_reuse::apply;

use crate::{
    credentials::{test_utils::new_credential, CredentialType},
    key_packages::KeyPackageBundle,
    treesync::{
        node::{encryption_keys::EncryptionKeyPair, Node},
        TreeSync,
    },
};

use openmls_rust_crypto::OpenMlsRustCrypto;

// Verifies that when we add a leaf to a tree with blank leaf nodes, the leaf will be added at the leftmost free leaf index
#[apply(ciphersuites_and_backends)]
fn test_free_leaf_computation(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (c_0, sk_0) = new_credential(
        backend,
        b"leaf0",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    let kpb_0 = KeyPackageBundle::new(backend, &sk_0, ciphersuite, c_0);

    let (c_3, sk_3) = new_credential(
        backend,
        b"leaf3",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let kpb_3 = KeyPackageBundle::new(backend, &sk_3, ciphersuite, c_3);

    // Build a rudimentary tree with two populated and two empty leaf nodes.
    let nodes: Vec<Option<Node>> = vec![
        Some(Node::LeafNode(
            kpb_0.key_package().leaf_node().clone().into(),
        )), // Leaf 0
        None,
        None, // Leaf 1
        None,
        None, // Leaf 2
        None,
        Some(Node::LeafNode(
            kpb_3.key_package().leaf_node().clone().into(),
        )), // Leaf 3
    ];

    // Get the encryption key pair from the leaf.
    let encryption_key_pair = EncryptionKeyPair::read_from_key_store(
        backend,
        kpb_0.key_package().leaf_node().encryption_key(),
    )
    .unwrap();

    let tree = TreeSync::from_nodes(
        backend,
        ciphersuite,
        &nodes,
        encryption_key_pair.public_key(),
    )
    .expect("error generating tree");

    // Create and add a new leaf. It should go to leaf index 1

    let (c_2, signer_2) = new_credential(
        backend,
        b"leaf2",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let kpb_2 = KeyPackageBundle::new(backend, &signer_2, ciphersuite, c_2);

    let mut diff = tree.empty_diff();
    let free_leaf_index = diff.free_leaf_index();
    let added_leaf_index = diff
        .add_leaf(kpb_2.key_package().leaf_node().clone().into())
        .expect("error adding leaf");
    assert_eq!(free_leaf_index.u32(), 1u32);
    assert_eq!(free_leaf_index, added_leaf_index);

    let free_leaf_index = diff.free_leaf_index();

    assert_eq!(free_leaf_index.u32(), 2u32);
}
