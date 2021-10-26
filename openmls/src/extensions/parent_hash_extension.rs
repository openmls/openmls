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

use tls_codec::{Size, TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};

#[derive(
    PartialEq, Clone, Debug, Default, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct ParentHashExtension {
    parent_hash: TlsByteVecU8,
}

impl ParentHashExtension {
    pub fn new(hash: &[u8]) -> Self {
        ParentHashExtension {
            parent_hash: hash.into(),
        }
    }

    /// Get a reference to the parent hash value.
    pub(crate) fn parent_hash(&self) -> &[u8] {
        self.parent_hash.as_slice()
    }
}
