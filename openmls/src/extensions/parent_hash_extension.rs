use tls_codec::{TlsByteVecU8, TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};

/// # Parent hash extension
///
/// The parent_hash extension serves to bind a KeyPackage to all the nodes
/// above it in the group's ratchet tree. This enforces the tree invariant,
/// meaning that malicious members can't lie about the state of the ratchet
/// tree when they send Welcome messages to new members.
///
/// This extension is present in all updates that are sent as part of a
/// commit message. If the extension is present, OpenMLS verifies that the
/// parent hash matches the hash of the leaf's parent node.
#[derive(
    PartialEq,
    Eq,
    Clone,
    Debug,
    Default,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
pub struct ParentHashExtension {
    parent_hash: TlsByteVecU8,
}

impl ParentHashExtension {
    /// Creates a new [`ParentHashExtension`] from a byte slice.
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
