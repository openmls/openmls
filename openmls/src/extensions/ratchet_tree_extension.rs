use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{Deserialize, Serialize};
use crate::treesync::{RatchetTree, RatchetTreeIn};

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
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct RatchetTreeExtension {
    ratchet_tree: RatchetTreeIn,
}

impl RatchetTreeExtension {
    /// Build a new extension from a vector of [`Node`](crate::treesync::node::Node)s.
    pub fn new(ratchet_tree: RatchetTree) -> Self {
        RatchetTreeExtension {
            ratchet_tree: ratchet_tree.into(),
        }
    }

    /// Return the [`RatchetTreeIn`] from this extension.
    pub fn ratchet_tree(&self) -> &RatchetTreeIn {
        &self.ratchet_tree
    }
}
