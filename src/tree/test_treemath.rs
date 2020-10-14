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

    for (i, r) in root.iter().enumerate() {
        assert_eq!(NodeIndex::from(*r), treemath::root(LeafIndex::from(i + 1)));
    }
    for (i, l) in left.iter().enumerate() {
        assert_eq!(NodeIndex::from(*l), treemath::left(NodeIndex::from(i)));
    }
    for (i, r) in right.iter().enumerate() {
        assert_eq!(
            NodeIndex::from(*r),
            treemath::right(NodeIndex::from(i), tree_size)
        );
    }
    for (i, p) in parent.iter().enumerate() {
        assert_eq!(
            NodeIndex::from(*p),
            treemath::parent(NodeIndex::from(i), tree_size)
        );
    }
    for (i, s) in sibling.iter().enumerate() {
        assert_eq!(
            NodeIndex::from(*s),
            treemath::sibling(NodeIndex::from(i), tree_size)
        );
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
            Vec::new(),
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
