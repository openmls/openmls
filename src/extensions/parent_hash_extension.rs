//! # Parent hash extension
//!
//! > KeyPackage Extension
//!
//! 7.4. Parent Hash
//!
//! The parent_hash extension serves to bind a KeyPackage to all the nodes
//! above it in the group's ratchet tree. This enforces the tree invariant,
//! meaning that malicious members can't lie about the state of the ratchet
//! tree when they send Welcome messages to new members.
//!
//! ```text
//! opaque parent_hash<0..255>;
//! ```
//!
//! This extension MUST be present in all Updates that are sent as part of a
//! Commit message. If the extension is present, clients MUST verify that
//! parent_hash matches the hash of the leaf's parent node when represented as a
//! ParentNode struct.

use super::{Extension, ExtensionType};
use crate::codec::{decode_vec, encode_vec, Cursor, VecSize};

#[derive(PartialEq, Clone, Debug)]
pub struct ParentHashExtension {
    pub parent_hash: Vec<u8>,
}

impl ParentHashExtension {
    pub fn new(hash: &[u8]) -> Self {
        ParentHashExtension {
            parent_hash: hash.to_vec(),
        }
    }
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let cursor = &mut Cursor::new(bytes);
        let parent_hash = decode_vec(VecSize::VecU8, cursor).unwrap();
        Self { parent_hash }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU8, &mut extension_data, &self.parent_hash).unwrap();
        let extension_type = ExtensionType::ParentHash;
        Extension {
            extension_type,
            extension_data,
        }
    }
}
