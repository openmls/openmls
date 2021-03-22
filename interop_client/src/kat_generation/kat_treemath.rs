fn generate_test_vectors() -> Vec<u8> {
    let mut tests = Vec::new();

    fn generate_test_vector(n_leaves: u32) -> TreeMathTestVector {
        let leaves = LeafIndex::from(n_leaves);
        let n_nodes = node_width(leaves.as_usize()) as u32;
        let mut test_vector = TreeMathTestVector {
            n_leaves,
            n_nodes,
            root: Vec::new(),
            left: Vec::new(),
            right: Vec::new(),
            parent: Vec::new(),
            sibling: Vec::new(),
        };

        for i in 0..n_leaves {
            test_vector.root.push(root(LeafIndex::from(i + 1)).as_u32());
            test_vector.left.push(convert!(left(NodeIndex::from(i))));
            test_vector
                .right
                .push(convert!(right(NodeIndex::from(i), leaves)));
            test_vector
                .parent
                .push(convert!(parent(NodeIndex::from(i), leaves)));
            test_vector
                .sibling
                .push(convert!(sibling(NodeIndex::from(i), leaves)));
        }

        test_vector
    }

    for n_leaves in 1..99 {
        let test_vector = generate_test_vector(n_leaves);
        tests.push(test_vector);
    }

    write("test_vectors/kat_treemath_openmls-new.json", &tests);
}
