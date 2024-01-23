//! # Known Answer Tests for treemath
//!
//! This test file generates and read test vectors for tree math.
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
//! for more description on the test vectors.
//!
//! ## Parameter:
//! Number of leaves `n_leaves`.
//!
//! ## Format:
//! ```text
//! {
//!     "cipher_suite": /* uint16 */,
//!     "root": /* uint32 */,
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
//! * `root` is the root node index of the tree
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
    root: u32,
    left: Vec<Option<u32>>,
    right: Vec<Option<u32>>,
    parent: Vec<Option<u32>>,
    sibling: Vec<Option<u32>>,
}

#[cfg(any(feature = "test-utils", test))]
pub fn generate_test_vector(n_leaves: u32) -> TreeMathTestVector {
    let n_nodes = TreeSize::new(node_width(n_leaves as usize) as u32);
    let mut test_vector = TreeMathTestVector {
        n_leaves,
        n_nodes: n_nodes.u32(),
        root: 0,
        left: Vec::new(),
        right: Vec::new(),
        parent: Vec::new(),
        sibling: Vec::new(),
    };

    test_vector.root = root(TreeSize::new(node_width(n_leaves as usize) as u32)).test_u32();
    for i in 0..n_nodes.u32() {
        let tree_index = TreeNodeIndex::test_new(i);

        match tree_index {
            TreeNodeIndex::Leaf(_) => {
                // Leaves don't have children
                test_vector.left.push(None);
                test_vector.right.push(None);
                // Exclude root
                let parent = if i != root(n_nodes).test_u32() {
                    Some(test_parent(tree_index).test_to_tree_index())
                } else {
                    None
                };
                test_vector.parent.push(parent);
                // Exclude root
                let sibling = if i != root(n_nodes).test_u32() {
                    Some(test_sibling(tree_index).test_u32())
                } else {
                    None
                };
                test_vector.sibling.push(sibling);
            }
            TreeNodeIndex::Parent(parent_index) => {
                test_vector.left.push(Some(left(parent_index).test_u32()));
                test_vector.right.push(Some(right(parent_index).test_u32()));
                // Exclude root
                let parent = if i != root(n_nodes).test_u32() {
                    Some(test_parent(tree_index).test_to_tree_index())
                } else {
                    None
                };
                test_vector.parent.push(parent);
                // Exclude root
                let sibling = if i != root(n_nodes).test_u32() {
                    Some(test_sibling(tree_index).test_u32())
                } else {
                    None
                };
                test_vector.sibling.push(sibling);
            }
        }
    }

    test_vector
}

#[test]
fn write_test_vectors() {
    let mut tests = Vec::new();

    for n_leaves in 0..10 {
        let test_vector = generate_test_vector(1 << n_leaves);
        tests.push(test_vector);
    }

    write("test_vectors/tree-math-new.json", &tests);
}

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(test_vector: TreeMathTestVector) -> Result<(), TmTestVectorError> {
    let n_leaves = test_vector.n_leaves as usize;
    let n_nodes = TreeSize::new(node_width(n_leaves) as u32);
    if test_vector.n_nodes != node_width(n_leaves) as u32 {
        return Err(TmTestVectorError::TreeSizeMismatch);
    }
    if test_vector.root != root(TreeSize::new(node_width(n_leaves) as u32)).test_u32() {
        return Err(TmTestVectorError::RootIndexMismatch);
    }

    for i in 0..n_nodes.u32() as usize {
        let tree_index = TreeNodeIndex::test_new(i as u32);
        match tree_index {
            TreeNodeIndex::Leaf(_) => {
                if test_vector.left[i].is_some() {
                    return Err(TmTestVectorError::LeftIndexMismatch);
                }
                if test_vector.right[i].is_some() {
                    return Err(TmTestVectorError::RightIndexMismatch);
                }

                if i != root(n_nodes).test_usize()
                    && test_vector.parent[i] != Some(test_parent(tree_index).test_to_tree_index())
                {
                    return Err(TmTestVectorError::ParentIndexMismatch);
                }

                if i != root(n_nodes).test_usize()
                    && test_vector.sibling[i] != Some(test_sibling(tree_index).test_u32())
                {
                    return Err(TmTestVectorError::SiblingIndexMismatch);
                }
            }
            TreeNodeIndex::Parent(parent_index) => {
                if test_vector.left[i] != Some(left(parent_index).test_u32()) {
                    return Err(TmTestVectorError::LeftIndexMismatch);
                }
                if test_vector.right[i] != Some(right(parent_index).test_u32()) {
                    return Err(TmTestVectorError::RightIndexMismatch);
                }

                if i != root(n_nodes).test_usize()
                    && test_vector.parent[i] != Some(test_parent(tree_index).test_to_tree_index())
                {
                    return Err(TmTestVectorError::ParentIndexMismatch);
                }

                if i != root(n_nodes).test_usize()
                    && test_vector.sibling[i] != Some(test_sibling(tree_index).test_u32())
                {
                    return Err(TmTestVectorError::SiblingIndexMismatch);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn read_test_vectors_tm() {
    let tests: Vec<TreeMathTestVector> = read_json!("../../../test_vectors/tree-math.json");
    for test_vector in tests {
        match run_test_vector(test_vector) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking tree math test vector.\n{e:?}"),
        }
    }
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
