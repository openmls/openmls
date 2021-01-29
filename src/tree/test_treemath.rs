use super::index::{LeafIndex, NodeIndex};
use super::treemath::{TreeMathError, _descendants, _descendants_alt};
use crate::config::*;
use crate::tree::{treemath, *};
use std::convert::TryFrom;
use std::fs::File;
use std::io::Read;

/// The following test uses an old test vector that assumes an outdated version
/// of the treemath defined in the spec. In a few select cases, we should now
/// expect errors based on the new treemath.
#[test]
fn verify_binary_test_vector_treemath() {
    let mut file = File::open("test_vectors/tree_math.bin").unwrap();
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).unwrap();

    let cursor = &mut Cursor::new(&buffer);

    let tree_size = LeafIndex::from(u32::decode(cursor).unwrap());

    let root: Vec<u32> = decode_vec(VecSize::VecU32, cursor).unwrap();
    let left: Vec<u32> = decode_vec(VecSize::VecU32, cursor).unwrap();
    let right: Vec<u32> = decode_vec(VecSize::VecU32, cursor).unwrap();
    let parent: Vec<u32> = decode_vec(VecSize::VecU32, cursor).unwrap();
    let sibling: Vec<u32> = decode_vec(VecSize::VecU32, cursor).unwrap();

    /// Take an index and entry of a test vector, as well as the result. If
    /// index and input are equal, this is an artefact of the old treemath and
    /// we have to expect the new treemath to raise an error.
    fn test_result(index: usize, input: u32, result: Result<NodeIndex, TreeMathError>) {
        if index != input as usize {
            assert!(result.is_ok());
            assert_eq!(NodeIndex::from(input), result.unwrap());
        } else {
            assert!(result.is_err());
        }
    }

    // Test if the `root` function is computed correctly according to the test
    // vector.
    for (i, &r) in root.iter().enumerate() {
        assert_eq!(NodeIndex::from(r), treemath::root(LeafIndex::from(i + 1)));
    }
    // Test if the `left` function is computed correctly according to the test
    // vector.
    for (i, &l) in left.iter().enumerate() {
        let result = treemath::left(NodeIndex::from(i));
        test_result(i, l, result);
    }
    // Test if the `right` function is computed correctly according to the test
    // vector.
    for (i, &r) in right.iter().enumerate() {
        let result = treemath::right(NodeIndex::from(i), tree_size);
        test_result(i, r, result);
    }
    // Test if the `parent` function is computed correctly according to the test
    // vector.
    for (i, &p) in parent.iter().enumerate() {
        let result = treemath::parent(NodeIndex::from(i), tree_size);
        test_result(i, p, result);
    }
    // Test if the `sibling` function is computed correctly according to the test
    // vector.
    for (i, &s) in sibling.iter().enumerate() {
        let result = treemath::sibling(NodeIndex::from(i), tree_size);
        test_result(i, s, result);
    }
    // There should be no other values in the test vector.
    assert_eq!(cursor.has_more(), false);
}

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
            let leaf_dir_path = treemath::leaf_direct_path(leaf_index, tree_size).unwrap();
            let parent_node = treemath::parent(NodeIndex::from(leaf_index), tree_size)
                .expect("Could not calculate parent node");
            let parent_direct_path = treemath::parent_direct_path(parent_node, tree_size)
                .expect("Could not calculate direct path");

            assert_eq!(leaf_dir_path, parent_direct_path);
        }
    }
}

#[test]
fn test_tree_hash() {
    fn create_identity(id: &[u8], ciphersuite_name: CiphersuiteName) -> KeyPackageBundle {
        let signature_scheme = SignatureScheme::from(ciphersuite_name);
        let credential_bundle =
            CredentialBundle::new(id.to_vec(), CredentialType::Basic, signature_scheme).unwrap();
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new()).unwrap()
    }

    for ciphersuite in Config::supported_ciphersuites() {
        let kbp = create_identity(b"Tree creator", ciphersuite.name());

        // Initialise tree
        let mut tree = RatchetTree::new(ciphersuite, kbp);
        let tree_hash = tree.tree_hash();
        println!("Tree hash: {:?}", tree_hash);

        // Add 5 nodes to the tree.
        let mut nodes = Vec::new();
        for _ in 0..5 {
            nodes.push(create_identity(b"Tree creator", ciphersuite.name()));
        }
        let key_packages: Vec<&KeyPackage> = nodes.iter().map(|kbp| &kbp.key_package).collect();
        let _ = tree.add_nodes(&key_packages);
        let tree_hash = tree.tree_hash();
        println!("Tree hash: {:?}", tree_hash);
    }
}

#[test]
fn verify_descendants() {
    const LEAVES: usize = 100;
    for size in 1..LEAVES {
        for node in 0..(size * 2 - 1) {
            assert_eq!(
                _descendants(NodeIndex::from(node), LeafIndex::from(size)),
                _descendants_alt(NodeIndex::from(node), LeafIndex::from(size))
            );
        }
    }
}
#[test]
fn test_treemath_functions() {
    assert_eq!(0, treemath::root(LeafIndex::from(0u32)).as_u32());
    // The tree with only one leaf has only one node, which is leaf and root at the same time.
    assert_eq!(0, treemath::root(LeafIndex::from(1u32)).as_u32());
    assert_eq!(1, treemath::root(LeafIndex::from(2u32)).as_u32());
    assert_eq!(3, treemath::root(LeafIndex::from(3u32)).as_u32());
}
