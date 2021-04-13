//! 7.4. Parent Hash
//!
//! struct {
//!     HPKEPublicKey public_key;
//!     opaque parent_hash<0..255>;
//!     HPKEPublicKey original_child_resolution<0..2^32-1>;
//! } ParentHashInput;
//!
//! 7.5. Tree Hashes
//!
//! ```text
//! struct {
//!     uint8 present;
//!     select (present) {
//!         case 0: struct{};
//!         case 1: T value;
//!     }
//! } optional<T>;
//!
//! struct {
//!     uint32 node_index;
//!     optional<KeyPackage> key_package;
//! } LeafNodeHashInput;
//!
//! struct {
//!     HPKEPublicKey public_key;
//!     opaque parent_hash<0..255>;
//!     uint32 unmerged_leaves<0..2^32-1>;
//! } ParentNode;
//!
//! struct {
//!     uint32 node_index;
//!     optional<ParentNode> parent_node;
//!     opaque left_hash<0..255>;
//!     opaque right_hash<0..255>;
//! } ParentNodeTreeHashInput;
//! ```

use super::node::ParentNode;
use super::*;
use crate::ciphersuite::{Ciphersuite, HPKEPublicKey};
use crate::codec::Codec;
use crate::key_packages::KeyPackage;

pub(crate) struct ParentHashInput<'a> {
    pub(crate) public_key: &'a HPKEPublicKey,
    pub(crate) parent_hash: &'a [u8],
    pub(crate) original_child_resolution: Vec<&'a HPKEPublicKey>,
}

impl<'a> ParentHashInput<'a> {
    pub(crate) fn new(
        tree: &'a RatchetTree,
        index: NodeIndex,
        child_index: NodeIndex,
        parent_hash: &'a [u8],
    ) -> Result<Self, ParentHashError> {
        let public_key = match tree.nodes[index].public_hpke_key() {
            Some(pk) => pk,
            None => return Err(ParentHashError::EmptyParentNode),
        };
        let original_child_resolution = tree.original_child_resolution(child_index);
        println!("original_child_resolution: {:?}", original_child_resolution);
        Ok(Self {
            public_key,
            parent_hash,
            original_child_resolution,
        })
    }
    pub(crate) fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}
pub struct LeafNodeHashInput<'a> {
    pub(crate) node_index: &'a NodeIndex,
    pub(crate) key_package: &'a Option<KeyPackage>,
}

impl<'a> LeafNodeHashInput<'a> {
    pub(crate) fn new(node_index: &'a NodeIndex, key_package: &'a Option<KeyPackage>) -> Self {
        Self {
            node_index,
            key_package,
        }
    }
    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}
pub struct ParentNodeTreeHashInput<'a> {
    pub(crate) node_index: u32,
    pub(crate) parent_node: &'a Option<ParentNode>,
    pub(crate) left_hash: &'a [u8],
    pub(crate) right_hash: &'a [u8],
}

impl<'a> ParentNodeTreeHashInput<'a> {
    pub(crate) fn new(
        node_index: u32,
        parent_node: &'a Option<ParentNode>,
        left_hash: &'a [u8],
        right_hash: &'a [u8],
    ) -> Self {
        Self {
            node_index,
            parent_node,
            left_hash,
            right_hash,
        }
    }
    pub(crate) fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}

// === Parent hashes ===

impl RatchetTree {
    /// The list of HPKEPublicKey values of the nodes in the resolution of
    /// `index` but with the `unmerged_leaves` of the parent node omitted.
    pub(crate) fn original_child_resolution(&self, index: NodeIndex) -> Vec<&HPKEPublicKey> {
        // Build the exclusion list that consists of the unmerged leaves of the parent
        // node
        let mut unmerged_leaves = vec![];
        // If the current index is not the root, we collect the unmerged leaves of the
        // parent
        if let Ok(parent_index) = treemath::parent(index, self.leaf_count()) {
            // Check if the parent node is not blank
            if let Some(parent_node) = &self.nodes[parent_index].node {
                for index in &parent_node.unmerged_leaves {
                    unmerged_leaves.push(NodeIndex::from(LeafIndex::from(*index as usize)));
                }
            }
        };
        // Convert the exclusion list to a HashSet for faster searching
        let exclusion_list: HashSet<&NodeIndex> = unmerged_leaves.iter().collect();

        // Compute the resolution for the index with the exclusion list
        let resolution = self.resolve(index, &exclusion_list);

        // Build the list of HPKE public keys by iterating over the resolution
        resolution
            .iter()
            .map(|index| self.nodes[*index].public_hpke_key().unwrap())
            .collect()
    }

    /// Computes the parent hashes for a leaf node and returns the parent hash
    /// for the parent hash extension
    pub(crate) fn set_parent_hashes(&mut self, index: LeafIndex) -> Vec<u8> {
        // Recursive helper function used to calculate parent hashes
        fn node_parent_hash(
            tree: &mut RatchetTree,
            index: NodeIndex,
            former_index: NodeIndex,
        ) -> Vec<u8> {
            let tree_size = tree.leaf_count();
            let root = treemath::root(tree_size);
            // When the group only has one member, there are no parent nodes
            if tree.leaf_count().as_usize() <= 1 {
                return vec![];
            }

            // Calculate the sibling of the former index
            // It is ok to use `unwrap()` here, since we never reach the root
            let former_index_sibling = treemath::sibling(former_index, tree_size).unwrap();
            // If we already reached the tree's root, return the hash of that node
            let parent_hash = if index == root {
                vec![]
            // Otherwise return the hash of the next parent
            } else {
                // Calculate the parent's index
                // It is ok to use `unwrap()` here, since we already checked that the index is
                // not the root
                let parent = treemath::parent(index, tree_size).unwrap();
                node_parent_hash(tree, parent, index)
            };
            // If the current node is a parent, replace the parent hash in that node
            let current_node = &mut tree.nodes[index];
            // Get the parent node
            if let Some(mut parent_node) = current_node.node.take() {
                // Set the parent hash
                parent_node.set_parent_hash(parent_hash);
                // Put the node back in the tree
                tree.nodes[index].node = Some(parent_node);
                // Calculate the parent hash of the current node and return it
                ParentHashInput::new(
                    tree,
                    index,
                    former_index_sibling,
                    &tree.nodes[index].node.as_ref().unwrap().parent_hash,
                )
                // It is ok to use `unwrap()` here, since we can be sure the node is not blank
                .unwrap()
                .hash(tree.ciphersuite)
            // Otherwise we reached the leaf level, just return the hash
            } else {
                parent_hash
            }
        }
        // The same index is used for the former index here, since that parameter is
        // ignored when starting with a leaf node
        node_parent_hash(self, index.into(), index.into())
    }

    /// Verify the parent hash of a tree node. Returns `Ok(())` if the parent
    /// hash has successfully been verified and `false` otherwise.
    pub fn verify_parent_hash(&self, index: NodeIndex, node: &Node) -> Result<(), ParentHashError> {
        // "Let L and R be the left and right children of P, respectively"
        let left = treemath::left(index).map_err(|_| ParentHashError::InputNotParentNode)?;
        let right = treemath::right(index, self.leaf_count()).unwrap();

        // Extract the parent hash field
        let parent_hash_field = node
            .parent_hash()
            .ok_or(ParentHashError::InputNotParentNode)?;

        // Current hash with right child resolution
        let current_hash_right =
            ParentHashInput::new(&self, index, right, parent_hash_field)?.hash(&self.ciphersuite);

        // "If L.parent_hash is equal to the Parent Hash of P with Co-Path Child R, the
        // check passes"
        if let Some(left_parent_hash_field) = self.nodes[left].parent_hash() {
            if left_parent_hash_field == current_hash_right {
                return Ok(());
            }
        }

        // "If R is blank, replace R with its left child until R is either non-blank or
        // a leaf node"
        let mut child = right;
        while self.nodes[child].is_blank() && child.is_parent() {
            // Unwrapping here is safe, because we know it is a full parent node
            child = treemath::left(child).unwrap();
        }
        let right = child;

        // "If R is a blank leaf node, the check fails"
        if self.nodes[child].is_blank() && right.is_leaf() {
            return Err(ParentHashError::EndedWithLeafNode);
        }

        // Current hash with left child resolution
        let current_hash_left = ParentHashInput::new(&self, index, left, parent_hash_field)
            // Unwrapping here is safe, since we can be sure the node is not blank
            .unwrap()
            .hash(&self.ciphersuite);

        // "If R.parent_hash is equal to the Parent Hash of P with Co-Path Child L, the
        // check passes"
        if let Some(right_parent_hash_field) = self.nodes[right].parent_hash() {
            if right_parent_hash_field == current_hash_left {
                return Ok(());
            }
        }

        // "Otherwise, the check fails"
        Err(ParentHashError::AllChecksFailed)
    }

    /// Verify the parent hashes of the tree nodes. Returns `true` if all parent
    /// hashes have successfully been verified and `false` otherwise.
    pub fn verify_parent_hashes(&self) -> Result<(), ParentHashError> {
        for (index, node) in self.nodes.iter().enumerate() {
            if NodeIndex::from(index).is_parent() && node.is_full_parent() {
                self.verify_parent_hash(NodeIndex::from(index), node)?;
            }
        }
        Ok(())
    }

    // === Tree hash ===

    /// Computes and returns the tree hash
    pub(crate) fn tree_hash(&self) -> Vec<u8> {
        // Recursive helper function to the tree hashes for a node
        fn node_hash(tree: &RatchetTree, index: NodeIndex) -> Vec<u8> {
            let node = &tree.nodes[index];
            // Depending on the node type, we calculate the hash differently
            match node.node_type {
                // For leaf nodes we just need the index and the KeyPackage
                NodeType::Leaf => {
                    let leaf_node_hash = LeafNodeHashInput::new(&index, &node.key_package);
                    leaf_node_hash.hash(tree.ciphersuite)
                }
                // For parent nodes we need the hash of the two children as well
                NodeType::Parent => {
                    // Unwrapping here is safe, because parent nodes always have children
                    let left = treemath::left(index).unwrap();
                    let left_hash = node_hash(tree, left);
                    let right = treemath::right(index, tree.leaf_count()).unwrap();
                    let right_hash = node_hash(tree, right);
                    let parent_node_hash = ParentNodeTreeHashInput::new(
                        index.as_u32(),
                        &node.node,
                        &left_hash,
                        &right_hash,
                    );
                    parent_node_hash.hash(tree.ciphersuite)
                }
            }
        }
        // We start with the root and traverse the tree downwards
        let root = treemath::root(self.leaf_count());
        node_hash(&self, root)
    }
}
