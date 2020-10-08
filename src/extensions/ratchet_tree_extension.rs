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
use crate::tree::node::*;

use super::{Extension, ExtensionType};

#[derive(PartialEq, Clone, Debug)]
pub struct RatchetTreeExtension {
    pub tree: Vec<Option<Node>>,
}

impl RatchetTreeExtension {
    pub fn new(tree: Vec<Option<Node>>) -> Self {
        RatchetTreeExtension { tree }
    }
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let cursor = &mut Cursor::new(bytes);
        let tree = decode_vec(VecSize::VecU32, cursor).unwrap();
        Self { tree }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU32, &mut extension_data, &self.tree).unwrap();
        let extension_type = ExtensionType::RatchetTree;
        Extension {
            extension_type,
            extension_data,
        }
    }
}
