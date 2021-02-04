//! # Known Answer Tests for treemath
//!
//! This test file generates and read test vectors for tree math.
//! This currently differs from the test vectors in https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! See https://github.com/mlswg/mls-implementations/issues/32 for a discussion.
//!
//! ## Parameter:
//! Number of leaves `n_leaves`.
//!
//! ## Format:
//! ```text
//! {
//!     "cipher_suite": /* uint16 */,
//!     "root": [ /* array of uint32 */ ],
//!     "left": [ /* array of option<uint32> */ ],
//!     "right": [ /* array of option<uint32> */ ],
//!     "parent": [ /* array of option<uint32> */ ],
//!     "sibling": [ /* array of option<uint32> */ ]
//! }
//! ```
//!
//! Any value that is invalid is represented as `null`.
//!
//! ## Verification:
//! * `root` is the node index of the left child of the root node index of the
//!   tree with `i+1` leaves.
//! * `left[i]` is the node index of the left child of the node with index `i`
//!   in a tree with `n_leaves` leaves
//! * `right[i]` is the node index of the right child of the node with index `i`
//!   in a tree with `n_leaves` leaves
//! * `parent[i]` is the node index of the parent of the node with index `i` in
//!   a tree with `n_leaves` leaves
//! * `sibling[i]` is the node index of the sibling of the node with index `i`
//!   in a tree with `n_leaves` leaves

use crate::{
    test_util::*,
    tree::{index::*, treemath::*},
};

use serde::{self, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TreeMathTestVector {
    n_leaves: u32,
    n_nodes: u32,
    root: Vec<u32>,
    left: Vec<Option<u32>>,
    right: Vec<Option<u32>>,
    parent: Vec<Option<u32>>,
    sibling: Vec<Option<u32>>,
}

macro_rules! convert {
    ($r:expr) => {
        match $r {
            Ok(i) => Some(i.as_u32()),
            Err(_) => None,
        }
    };
}

#[test]
fn generate_test_vectors() {
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

#[test]
fn run_test_vectors() {
    let tests: Vec<TreeMathTestVector> = read("test_vectors/kat_treemath_openmls.json");

    for test_vector in tests {
        let n_leaves = test_vector.n_leaves;
        let leaves = LeafIndex::from(n_leaves);
        assert_eq!(test_vector.n_nodes, node_width(leaves.as_usize()) as u32);

        for i in 0..(n_leaves as usize) {
            assert_eq!(test_vector.root[i], root(LeafIndex::from(i + 1)).as_u32());
            assert_eq!(test_vector.left[i], convert!(left(NodeIndex::from(i))));
            assert_eq!(
                test_vector.right[i],
                convert!(right(NodeIndex::from(i), leaves))
            );
            assert_eq!(
                test_vector.parent[i],
                convert!(parent(NodeIndex::from(i), leaves))
            );
            assert_eq!(
                test_vector.sibling[i],
                convert!(sibling(NodeIndex::from(i), leaves))
            );
        }
    }
}
