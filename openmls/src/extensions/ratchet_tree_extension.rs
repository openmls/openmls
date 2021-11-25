//! # Ratchet tree extension
//!
//! > GroupInfo Extension
//!
//! 11.3. Ratchet Tree Extension
//!
//! ```text
//! enum {
//!     reserved(0),
//!     leaf(1),
//!     parent(2),
//!     (255)
//! } NodeType;
//!
//! struct {
//!     NodeType node_type;
//!     select (Node.node_type) {
//!         case leaf:   KeyPackage key_package;
//!         case parent: ParentNode node;
//!     };
//! } Node;
//!
//! optional<Node> ratchet_tree<1..2^32-1>;
//! ```
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use super::{Deserialize, Serialize};
use crate::tree::node::*;

#[derive(
    PartialEq, Clone, Debug, Default, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct RatchetTreeExtension {
    tree: TlsVecU32<Option<Node>>,
}

impl RatchetTreeExtension {
    /// Build a new extension from a vector of `Node`s.
    pub fn new(tree: Vec<Option<Node>>) -> Self {
        RatchetTreeExtension { tree: tree.into() }
    }

    /// Get a slice of the nodes in tis tree.
    pub(crate) fn as_slice(&self) -> &[Option<Node>] {
        self.tree.as_slice()
    }
}
