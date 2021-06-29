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
use crate::codec::*;
use crate::tree::node::*;

use super::{
    Deserialize, Extension, ExtensionError, ExtensionStruct, ExtensionType, RatchetTreeError,
    Serialize,
};

#[derive(PartialEq, Clone, Debug, Default, Serialize, Deserialize)]
pub struct RatchetTreeExtension {
    tree: Vec<Option<Node>>,
}

impl RatchetTreeExtension {
    /// Build a new extension from a vector of `Node`s.
    pub fn new(tree: Vec<Option<Node>>) -> Self {
        RatchetTreeExtension { tree }
    }

    pub fn into_vector(self) -> Vec<Option<Node>> {
        self.tree
    }
}

#[typetag::serde]
impl Extension for RatchetTreeExtension {
    fn extension_type(&self) -> ExtensionType {
        ExtensionType::RatchetTree
    }

    /// Build a new RatchetTreeExtension from a byte slice.
    fn new_from_bytes(bytes: &[u8]) -> Result<Self, ExtensionError>
    where
        Self: Sized,
    {
        let cursor = &mut Cursor::new(bytes);
        match decode_vec(VecSize::VecU32, cursor) {
            Ok(tree) => Ok(Self { tree }),
            Err(_) => Err(ExtensionError::RatchetTree(RatchetTreeError::Invalid)),
        }
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
