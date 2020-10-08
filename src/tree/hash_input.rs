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
//!     HPKEPublicKey public_key;
//!     uint32 unmerged_leaves<0..2^32-1>;
//!     opaque parent_hash<0..255>;
//! } ParentNode;
//!
//! struct {
//!     uint32 node_index;
//!     optional<ParentNode> parent_node;
//!     opaque left_hash<0..255>;
//!     opaque right_hash<0..255>;
//! } ParentNodeHashInput;
//!
//! struct {
//!     uint32 node_index;
//!     optional<KeyPackage> key_package;
//! } LeafNodeHashInput;
//! ```
//!

use super::index::NodeIndex;
use super::node::ParentNode;
use crate::ciphersuite::Ciphersuite;
use crate::codec::{encode_vec, Codec, CodecError, VecSize};
use crate::key_packages::KeyPackage;

pub struct ParentNodeHashInput<'a> {
    node_index: u32,
    parent_node: &'a Option<ParentNode>,
    left_hash: &'a [u8],
    right_hash: &'a [u8],
}

impl<'a> ParentNodeHashInput<'a> {
    pub fn new(
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
    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Vec<u8> {
        let payload = self.encode_detached().unwrap();
        ciphersuite.hash(&payload)
    }
}

pub struct LeafNodeHashInput<'a> {
    node_index: &'a NodeIndex,
    key_package: &'a Option<KeyPackage>,
}

impl<'a> LeafNodeHashInput<'a> {
    pub fn new(node_index: &'a NodeIndex, key_package: &'a Option<KeyPackage>) -> Self {
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

impl<'a> Codec for ParentNodeHashInput<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_index.encode(buffer)?;
        self.parent_node.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.left_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.right_hash)?;
        Ok(())
    }
}

impl<'a> Codec for LeafNodeHashInput<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_index.as_u32().encode(buffer)?;
        self.key_package.encode(buffer)?;
        Ok(())
    }
}
