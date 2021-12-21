use openmls_traits::OpenMlsCryptoProvider;
use rstest::*;
use rstest_reuse::apply;

use crate::{
    ciphersuite::CiphersuiteName,
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    prelude::KeyPackageBundle,
    prelude_test::{node::Node, Ciphersuite, TreeSync},
};

use openmls_rust_crypto::OpenMlsRustCrypto;

// Verifies that when we add a leaf to a tree with blank leaf nodes, the leaf will be added at the leftmost free leaf index
#[apply(ciphersuites_and_backends)]
fn test_free_leaf_computation(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let cb_0 = CredentialBundle::new(
        "leaf0".as_bytes().to_vec(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("error creating credential_bundle");

    let kpb_0 = KeyPackageBundle::new(&[ciphersuite.name()], &cb_0, backend, vec![])
        .expect("error creating kpb");

    let cb_3 = CredentialBundle::new(
        "leaf3".as_bytes().to_vec(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("error creating credential_bundle");
    let kpb_3 = KeyPackageBundle::new(&[ciphersuite.name()], &cb_3, backend, vec![])
        .expect("error creating kpb");

    // Build a rudimentary tree with two populated and two empty leaf nodes.
    let nodes: Vec<Option<Node>> = vec![
        Some(Node::LeafNode(kpb_0.key_package().clone().into())), // Leaf 0
        None,
        None, // Leaf 1
        None,
        None, // Leaf 2
        None,
        Some(Node::LeafNode(kpb_3.key_package().clone().into())), // Leaf 3
    ];
    let tree =
        TreeSync::from_nodes(backend, ciphersuite, &nodes, kpb_0).expect("error generating tree");

    // Create and add a new leaf. It should go to leaf index 1

    let cb_2 = CredentialBundle::new(
        "leaf2".as_bytes().to_vec(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("error creating credential_bundle");
    let kpb_2 = KeyPackageBundle::new(&[ciphersuite.name()], &cb_2, backend, vec![])
        .expect("error creating kpb");

    let mut diff = tree.empty_diff().expect("error creating empty diff");
    let free_leaf_index = diff
        .add_leaf(kpb_2.key_package().clone())
        .expect("error adding leaf");

    assert_eq!(free_leaf_index, 1u32);
}
