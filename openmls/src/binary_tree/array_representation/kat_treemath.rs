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

#[cfg(test)]
use crate::test_utils::*;

use super::treemath::*;

use serde::{self, Deserialize, Serialize};
use thiserror::Error;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TreeMathTestVector {
    n_leaves: u32,
    n_nodes: u32,
    root: Vec<u32>,
    left: Vec<Option<u32>>,
    right: Vec<Option<u32>>,
    parent: Vec<Option<u32>>,
    sibling: Vec<Option<u32>>,
}

#[cfg(any(feature = "test-utils", test))]
pub fn generate_test_vector(n_leaves: u32) -> TreeMathTestVector {
    let n_nodes = node_width(n_leaves as usize) as u32;
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
        test_vector
            .root
            .push(root(node_width(i as usize + 1) as u32));
    }
    for i in 0..n_nodes {
        test_vector.left.push(left(i).ok());
        test_vector.right.push(right(i, n_nodes).ok());
        test_vector.parent.push(parent(i, n_nodes).ok());
        test_vector.sibling.push(sibling(i, n_nodes).ok());
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

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(test_vector: TreeMathTestVector) -> Result<(), TmTestVectorError> {
    let n_leaves = test_vector.n_leaves as usize;
    let n_nodes = node_width(n_leaves);
    let nodes = n_nodes as u32;
    if test_vector.n_nodes != node_width(n_leaves) as u32 {
        return Err(TmTestVectorError::TreeSizeMismatch);
    }
    for i in 0..n_leaves {
        if test_vector.root[i] != root(node_width(i + 1) as u32) {
            return Err(TmTestVectorError::RootIndexMismatch);
        }
    }

    for i in 0..n_nodes {
        if test_vector.left[i] != left(i as u32).ok() {
            return Err(TmTestVectorError::LeftIndexMismatch);
        }
        if test_vector.right[i] != right(i as u32, nodes).ok() {
            return Err(TmTestVectorError::RightIndexMismatch);
        }
        if test_vector.parent[i] != parent(i as u32, nodes).ok() {
            return Err(TmTestVectorError::ParentIndexMismatch);
        }
        if test_vector.sibling[i] != sibling(i as u32, nodes).ok() {
            return Err(TmTestVectorError::SiblingIndexMismatch);
        }
    }
    Ok(())
}

#[test]
fn read_test_vectors_tm() {
    let tests: Vec<TreeMathTestVector> = read("test_vectors/kat_treemath_openmls.json");
    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking tree math test vector.\n{:?}", e),
        }
    }

    // mlspp test vector
    let tv: TreeMathTestVector = read("test_vectors/mlspp/mlspp_treemath.json");
    run_test_vector(tv).expect("Error while checking key schedule test vector.");
}

#[cfg(any(feature = "test-utils", test))]
/// TreeMath test vector error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum TmTestVectorError {
    /// The computed tree size doesn't match the one in the test vector.
    #[error("The computed tree size doesn't match the one in the test vector.")]
    TreeSizeMismatch,
    /// The computed root index doesn't match the one in the test vector.
    #[error("The computed root index doesn't match the one in the test vector.")]
    RootIndexMismatch,
    /// A computed left child index doesn't match the one in the test vector.
    #[error("A computed left child index doesn't match the one in the test vector.")]
    LeftIndexMismatch,
    /// A computed right child index doesn't match the one in the test vector.
    #[error("A computed right child index doesn't match the one in the test vector.")]
    RightIndexMismatch,
    /// A computed parent index doesn't match the one in the test vector.
    #[error("A computed parent index doesn't match the one in the test vector.")]
    ParentIndexMismatch,
    /// A computed sibling index doesn't match the one in the test vector.
    #[error("A computed sibling index doesn't match the one in the test vector.")]
    SiblingIndexMismatch,
}
