use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;

use crate::{
    
    test_utils::*,
    tree::{
        index::{LeafIndex, NodeIndex},
        treemath::{self, descendants, descendants_alt, TreeMathError},
        *,
    },
};
use std::convert::TryFrom;

/// Tests the variants of the direct path calculations.
/// Expected result:
///  - dirpath contains the direct path
///  - direct_path_root contains the direct path and the root
///  - dirpath_long contains the leaf, the direct path and the root
#[test]
fn test_dir_path() {
    const SIZE: u32 = 100;
    for size in 0..SIZE {
        for i in (0..size / 2).step_by(2) {
            let leaf_index = LeafIndex::try_from(i).expect("Could not create LeafIndex");
            let tree_size = LeafIndex::from(size);
            let leaf_dir_path = treemath::leaf_direct_path(leaf_index, tree_size)
                .expect("An unexpected error occurred.");
            let parent_node = treemath::parent(NodeIndex::from(leaf_index), tree_size)
                .expect("Could not calculate parent node");
            let parent_direct_path = treemath::parent_direct_path(parent_node, tree_size)
                .expect("Could not calculate direct path");

            assert_eq!(leaf_dir_path, parent_direct_path);
        }
    }
}

#[apply(ciphersuites_and_backends)]
fn test_tree_hash(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    fn create_identity(
        id: &[u8],
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
    ) -> KeyPackageBundle {
        let signature_scheme = SignatureScheme::from(ciphersuite);
        let credential_bundle = CredentialBundle::new(
            id.to_vec(),
            CredentialType::Basic,
            signature_scheme,
            backend,
        )
        .expect("An unexpected error occurred.");
        KeyPackageBundle::new(
            &[ciphersuite],
            &credential_bundle,
            backend,
            Vec::new(),
        )
        .expect("An unexpected error occurred.")
    }

    let kbp = create_identity(b"Tree creator", ciphersuite, backend);

    // Initialise tree
    let mut tree = RatchetTree::new(backend, kbp).expect("Could not create PrivateTree.");
    let tree_hash = tree.tree_hash(backend);
    println!("Tree hash: {:?}", tree_hash);

    // Add 5 nodes to the tree.
    let mut nodes = Vec::new();
    for _ in 0..5 {
        nodes.push(create_identity(b"Tree creator", ciphersuite, backend));
    }
    let key_packages: Vec<&KeyPackage> = nodes.iter().map(|kbp| &kbp.key_package).collect();
    let _ = tree.add_nodes(&key_packages);
    let tree_hash = tree.tree_hash(backend);
    println!("Tree hash: {:?}", tree_hash);
}

#[test]
fn verify_descendants() {
    const LEAVES: usize = 100;
    for size in 1..LEAVES {
        for node in 0..(size * 2 - 1) {
            assert_eq!(
                descendants(NodeIndex::from(node), LeafIndex::from(size)),
                descendants_alt(NodeIndex::from(node), LeafIndex::from(size))
                    .expect("Error when computing descendants occurred.")
            );
        }
    }
}
#[test]
fn test_treemath_functions() {
    assert_eq!(0, treemath::root(LeafIndex::from(0u32)).as_u32());
    // The tree with only one leaf has only one node, which is leaf and root at the
    // same time.
    assert_eq!(0, treemath::root(LeafIndex::from(1u32)).as_u32());
    assert_eq!(1, treemath::root(LeafIndex::from(2u32)).as_u32());
    assert_eq!(3, treemath::root(LeafIndex::from(3u32)).as_u32());
}

#[test]
fn invalid_inputs() {
    assert_eq!(
        Err(TreeMathError::LeafNotInTree),
        treemath::leaf_direct_path(3u32.into(), 2u32.into())
    );
    assert_eq!(
        Err(TreeMathError::NodeNotInTree),
        treemath::parent_direct_path(3u32.into(), 2u32.into())
    );
    assert_eq!(
        Err(TreeMathError::LeafNotInTree),
        treemath::copath(10u32.into(), 5u32.into())
    );
    assert_eq!(
        Err(TreeMathError::NodeNotInTree),
        treemath::parent(1000u32.into(), 100u32.into())
    );
}
