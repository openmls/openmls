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

    fn test_result(index: usize, input: &u32, result: Result<NodeIndex, TreeMathError>) {
        if index != *input as usize {
            assert!(result.is_ok());
            assert_eq!(NodeIndex::from(*input), result.unwrap());
        } else {
            assert!(result.is_err());
        }
    }

    for (i, r) in root.iter().enumerate() {
        assert_eq!(NodeIndex::from(*r), treemath::root(LeafIndex::from(i + 1)));
    }
    for (i, l) in left.iter().enumerate() {
        let result = treemath::left(NodeIndex::from(i));
        test_result(i, l, result);
    }
    for (i, r) in right.iter().enumerate() {
        let result = treemath::right(NodeIndex::from(i), tree_size);
        test_result(i, r, result);
    }
    for (i, p) in parent.iter().enumerate() {
        let result = treemath::parent(NodeIndex::from(i), tree_size);
        test_result(i, p, result);
    }
    for (i, s) in sibling.iter().enumerate() {
        let result = treemath::sibling(NodeIndex::from(i), tree_size);
        test_result(i, s, result);
    }
    assert_eq!(cursor.has_more(), false);
}

#[test]
fn test_tree_hash() {
    use crate::ciphersuite::*;
    use crate::creds::*;
    use crate::tree::*;

    fn create_identity(id: &[u8], ciphersuite: &Ciphersuite) -> KeyPackageBundle {
        let signature_keypair = ciphersuite.new_signature_keypair();
        let identity = Identity::new(*ciphersuite, id.to_vec());
        let credential = Credential::Basic(BasicCredential::from(&identity));
        let kbp = KeyPackageBundle::new(
            &ciphersuite,
            signature_keypair.get_private_key(),
            credential,
            None,
        );
        kbp
    }

    let csuite = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let ciphersuite = Ciphersuite::new(csuite);
    let kbp = create_identity(b"Tree creator", &ciphersuite);

    // Initialise tree
    let mut tree = RatchetTree::new(ciphersuite, kbp);
    let tree_hash = tree.compute_tree_hash();
    println!("Tree hash: {:?}", tree_hash);

    // Add 5 nodes to the tree.
    let mut nodes = Vec::new();
    for _ in 0..5 {
        nodes.push(create_identity(b"Tree creator", &ciphersuite));
    }
    let key_packages: Vec<KeyPackage> = nodes.iter().map(|kbp| kbp.key_package.clone()).collect();
    let _ = tree.add_nodes(&key_packages);
    let tree_hash = tree.compute_tree_hash();
    println!("Tree hash: {:?}", tree_hash);
}
