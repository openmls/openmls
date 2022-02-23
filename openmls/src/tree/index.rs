use std::convert::TryFrom;
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

use super::*;

/// NodeIndex is an index to the nodes of a tree, both parent and leaf nodes.
#[derive(
    Debug,
    Ord,
    PartialOrd,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Hash,
    Default,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
pub(crate) struct SecretTreeNodeIndex(u32);

impl SecretTreeNodeIndex {
    pub(crate) fn as_u32(self) -> u32 {
        self.0
    }
    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }
    pub(crate) fn is_parent(&self) -> bool {
        self.0 % 2 == 1
    }
}

impl From<u32> for SecretTreeNodeIndex {
    fn from(i: u32) -> SecretTreeNodeIndex {
        SecretTreeNodeIndex(i)
    }
}

impl From<usize> for SecretTreeNodeIndex {
    fn from(i: usize) -> SecretTreeNodeIndex {
        SecretTreeNodeIndex(i as u32)
    }
}

impl From<SecretTreeLeafIndex> for SecretTreeNodeIndex {
    fn from(node_index: SecretTreeLeafIndex) -> SecretTreeNodeIndex {
        SecretTreeNodeIndex(node_index.as_u32() * 2)
    }
}

/// LeafIndex is an index to the leaves of a tree.
#[derive(
    Debug,
    Default,
    Ord,
    PartialOrd,
    Hash,
    Eq,
    PartialEq,
    Copy,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub(crate) struct SecretTreeLeafIndex(pub(crate) u32);

impl SecretTreeLeafIndex {
    pub(crate) fn as_u32(self) -> u32 {
        self.0
    }
    pub(crate) fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl From<u32> for SecretTreeLeafIndex {
    fn from(i: u32) -> SecretTreeLeafIndex {
        SecretTreeLeafIndex(i)
    }
}

impl From<usize> for SecretTreeLeafIndex {
    fn from(i: usize) -> SecretTreeLeafIndex {
        SecretTreeLeafIndex(i as u32)
    }
}

impl From<SecretTreeLeafIndex> for u32 {
    fn from(i: SecretTreeLeafIndex) -> u32 {
        i.as_u32()
    }
}

impl From<SecretTreeLeafIndex> for usize {
    fn from(i: SecretTreeLeafIndex) -> usize {
        i.as_usize()
    }
}

impl TryFrom<SecretTreeNodeIndex> for SecretTreeLeafIndex {
    type Error = &'static str;
    fn try_from(node_index: SecretTreeNodeIndex) -> Result<Self, Self::Error> {
        // A node with an odd index must be a parent node and therefore cannot be
        // converted to a leaf node
        if node_index.is_parent() {
            Err("Cannot convert a parent node index to a leaf node index.")
        } else {
            Ok(SecretTreeLeafIndex((node_index.as_u32() + 1) / 2))
        }
    }
}
