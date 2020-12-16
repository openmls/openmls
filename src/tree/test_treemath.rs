use super::treemath::TreeMathError;

/// The following test uses an old test vector that assumes an outdated version
/// of the treemath defined in the spec. In a few select cases, we should now
/// expect errors based on the new treemath.
#[test]
fn verify_binary_test_vector_treemath() {
    use crate::tree::treemath;
    use crate::tree::*;
    use std::fs::File;
    use std::io::Read;

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
    use crate::tree::{treemath::*, *};
    const SIZE: u32 = 100;
    for size in 0..SIZE {
        for i in 0..size / 2 {
            let index = NodeIndex::from(i);
            let mut dir_path_test = dirpath(index, LeafIndex::from(size)).unwrap();
            let root = root(LeafIndex::from(size));
            dir_path_test.extend_from_slice(&[root]);
            assert_eq!(
                dir_path_test,
                direct_path_root(index, LeafIndex::from(size)).unwrap()
            );
            let mut dirpath_long_test = vec![index];
            dirpath_long_test.extend(dir_path_test);
            assert_eq!(
                dirpath_long_test,
                dirpath_long(index, LeafIndex::from(size)).unwrap()
            );
        }
    }
}

#[test]
fn test_tree_hash() {
    use crate::ciphersuite::*;
    use crate::config::*;
    use crate::credentials::*;
    use crate::tree::*;

    fn create_identity(id: &[u8], ciphersuite_name: CiphersuiteName) -> KeyPackageBundle {
        let credential_bundle =
            CredentialBundle::new(id.to_vec(), CredentialType::Basic, ciphersuite_name).unwrap();
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new()).unwrap()
    }

    for ciphersuite in Config::supported_ciphersuites() {
        let kbp = create_identity(b"Tree creator", ciphersuite.name());

        // Initialise tree
        let mut tree = RatchetTree::new(ciphersuite, kbp);
        let tree_hash = tree.compute_tree_hash();
        println!("Tree hash: {:?}", tree_hash);

        // Add 5 nodes to the tree.
        let mut nodes = Vec::new();
        for _ in 0..5 {
            nodes.push(create_identity(b"Tree creator", ciphersuite.name()));
        }
        let key_packages: Vec<&KeyPackage> = nodes.iter().map(|kbp| &kbp.key_package).collect();
        let _ = tree.add_nodes(&key_packages);
        let tree_hash = tree.compute_tree_hash();
        println!("Tree hash: {:?}", tree_hash);
    }
}
