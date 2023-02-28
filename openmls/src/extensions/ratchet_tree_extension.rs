use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};
use crate::treesync::RatchetTree;

/// # Ratchet Tree Extension.
///
/// The ratchet tree extension contains a list of (optional) [`Node`](crate::treesync::node::Node)s that
/// represent the public state of the tree in an MLS group.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// optional<Node> ratchet_tree<V>;
/// ```
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
pub struct RatchetTreeExtension {
    ratchet_tree: RatchetTree,
}

impl RatchetTreeExtension {
    /// Build a new extension from a vector of [`Node`](crate::treesync::node::Node)s.
    pub fn new(ratchet_tree: RatchetTree) -> Self {
        RatchetTreeExtension { ratchet_tree }
    }

    /// Return the [`RatchetTreeExported`] from this extension.
    pub fn ratchet_tree(&self) -> &RatchetTree {
        &self.ratchet_tree
    }
}
