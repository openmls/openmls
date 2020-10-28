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
//!
use crate::codec::*;
use crate::errors::ConfigError;
use crate::tree::node::*;

use super::{Extension, ExtensionStruct, ExtensionType};

#[derive(PartialEq, Clone, Debug, Default)]
pub struct RatchetTreeExtension {
    tree: Vec<Option<Node>>,
}

impl RatchetTreeExtension {
    /// Build a new extension from a vector of `Node`s.
    pub(crate) fn new(tree: Vec<Option<Node>>) -> Self {
        RatchetTreeExtension { tree }
    }

    pub(crate) fn into_vector(self) -> Vec<Option<Node>> {
        self.tree
    }
}

impl Extension for RatchetTreeExtension {
    fn get_type(&self) -> ExtensionType {
        ExtensionType::RatchetTree
    }

    /// Build a new RatchetTreeExtension from a byte slice.
    fn new_from_bytes(bytes: &[u8]) -> Result<Self, ConfigError>
    where
        Self: Sized,
    {
        let cursor = &mut Cursor::new(bytes);
        let tree = decode_vec(VecSize::VecU32, cursor).unwrap();
        Ok(Self { tree })
    }

    fn to_extension_struct(&self) -> ExtensionStruct {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU32, &mut extension_data, &self.tree).unwrap();
        let extension_type = ExtensionType::RatchetTree;
        ExtensionStruct::new(extension_type, extension_data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
