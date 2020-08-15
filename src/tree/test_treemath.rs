
#[test]
fn verify_binary_test_vector_treemath() {
    use crate::tree::*;
    use crate::tree::treemath;
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
