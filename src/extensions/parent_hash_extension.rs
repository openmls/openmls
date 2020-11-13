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

use super::{Extension, ExtensionStruct, ExtensionType};
use crate::codec::{decode_vec, encode_vec, Cursor, VecSize};
use crate::errors::ConfigError;

#[derive(PartialEq, Clone, Debug, Default)]
pub struct ParentHashExtension {
    parent_hash: Vec<u8>,
}

impl ParentHashExtension {
    pub fn new(hash: &[u8]) -> Self {
        ParentHashExtension {
            parent_hash: hash.to_vec(),
        }
    }

    /// Get a reference to the parent hash value.
    pub(crate) fn parent_hash(&self) -> &[u8] {
        &self.parent_hash
    }
}

impl Extension for ParentHashExtension {
    fn get_type(&self) -> ExtensionType {
        ExtensionType::ParentHash
    }

    /// Build a new ParentHashExtension from a byte slice.
    fn new_from_bytes(bytes: &[u8]) -> Result<Self, ConfigError>
    where
        Self: Sized,
    {
        let cursor = &mut Cursor::new(bytes);
        let parent_hash = decode_vec(VecSize::VecU8, cursor)?;
        Ok(Self { parent_hash })
    }

    fn to_extension_struct(&self) -> ExtensionStruct {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU8, &mut extension_data, &self.parent_hash).unwrap();
        let extension_type = ExtensionType::ParentHash;
        ExtensionStruct::new(extension_type, extension_data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
