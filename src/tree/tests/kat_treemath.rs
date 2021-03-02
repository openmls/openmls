//! # Known Answer Tests for treemath
//!
//! This test file generates and read test vectors for tree math.
//! See https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! for more description on the test vectors.
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
//! * `n_nodes` is the number of nodes in the tree with `n_leaves` leaves
//! * `root[i]` is the root node index of the tree with `i+1` leaves
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

#[cfg(any(feature = "expose-test-vectors", test))]
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

#[test]
fn write_test_vectors() {
    let mut tests = Vec::new();

    for n_leaves in 1..99 {
        let test_vector = generate_test_vector(n_leaves);
        tests.push(test_vector);
    }

    write("test_vectors/kat_treemath_openmls-new.json", &tests);
}

#[cfg(any(feature = "expose-test-vectors", test))]
fn run_test_vector(test_vector: TreeMathTestVector) -> Result<(), TMTestVectorError> {
    let n_leaves = test_vector.n_leaves;
    let leaves = LeafIndex::from(n_leaves);
    if test_vector.n_nodes != node_width(leaves.as_usize()) as u32 {
        return Err(TMTestVectorError::TreeSizeMismatch);
    }

    for i in 0..(n_leaves as usize) {
        if test_vector.root[i] != root(LeafIndex::from(i + 1)).as_u32() {
            return Err(TMTestVectorError::RootIndexMismatch);
        }
        if test_vector.left[i] != convert!(left(NodeIndex::from(i))) {
            return Err(TMTestVectorError::LeftIndexMismatch);
        }
        if test_vector.right[i] != convert!(right(NodeIndex::from(i), leaves)) {
            return Err(TMTestVectorError::RightIndexMismatch);
        }
        if test_vector.parent[i] != convert!(parent(NodeIndex::from(i), leaves)) {
            return Err(TMTestVectorError::ParentIndexMismatch);
        }
        if test_vector.sibling[i] != convert!(sibling(NodeIndex::from(i), leaves)) {
            return Err(TMTestVectorError::SiblingIndexMismatch);
        }
    }
    Ok(())
}

#[test]
fn read_test_vectors() {
    let tests: Vec<TreeMathTestVector> = read("test_vectors/kat_treemath_openmls.json");
    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking tree math test vector.\n{:?}", e),
        }
    }
}

#[cfg(any(feature = "expose-test-vectors", test))]
implement_error! {
    pub enum TMTestVectorError {
        TreeSizeMismatch = "The computed tree size doesn't match the one in the test vector.",
        RootIndexMismatch = "The computed root index doesn't match the one in the test vector.",
        LeftIndexMismatch = "A computed left child index doesn't match the one in the test vector.",
        RightIndexMismatch = "A computed right child index doesn't match the one in the test vector.",
        ParentIndexMismatch = "A computed parent index doesn't match the one in the test vector.",
        SiblingIndexMismatch = "A computed sibling index doesn't match the one in the test vector.",
    }
}
