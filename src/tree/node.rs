use crate::ciphersuite::*;
use crate::codec::*;
use crate::extensions::*;

use super::*;

#[derive(PartialEq, Clone, Copy, Debug, Serialize, Deserialize)]
#[repr(u8)]
pub enum NodeType {
    Leaf = 0,
    Parent = 1,
    Default = 255,
}

impl From<u8> for NodeType {
    fn from(value: u8) -> Self {
        match value {
            0 => NodeType::Leaf,
            1 => NodeType::Parent,
            _ => NodeType::Default,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Node {
    pub node_type: NodeType,
    // The node only holds public values.
    // The private HPKE keys are stored in the `PrivateTree`.
    pub(crate) key_package: Option<KeyPackage>,
    pub(crate) node: Option<ParentNode>,
}

impl Node {
    pub fn new_leaf(kp_option: Option<KeyPackage>) -> Self {
        Node {
            node_type: NodeType::Leaf,
            key_package: kp_option,
            node: None,
        }
    }
    pub fn new_blank_parent_node() -> Self {
        Node {
            node_type: NodeType::Parent,
            key_package: None,
            node: None,
        }
    }
    pub fn public_hpke_key(&self) -> Option<&HPKEPublicKey> {
        match self.node_type {
            NodeType::Leaf => {
                if let Some(ref kp) = self.key_package {
                    Some(kp.hpke_init_key())
                } else {
                    None
                }
            }
            NodeType::Parent => {
                if let Some(ref parent_node) = self.node {
                    Some(&parent_node.public_key)
                } else {
                    None
                }
            }
            NodeType::Default => None,
        }
    }
    pub fn blank(&mut self) {
        self.key_package = None;
        self.node = None;
    }
    pub fn is_blank(&self) -> bool {
        self.key_package.is_none() && self.node.is_none()
    }
    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Option<Vec<u8>> {
        if let Some(parent_node) = &self.node {
            let payload = parent_node.encode_detached().unwrap();
            let node_hash = ciphersuite.hash(&payload);
            Some(node_hash)
        } else {
            None
        }
    }

    // TODO: #98 should this really return a vec?
    pub fn parent_hash(&self) -> Option<Vec<u8>> {
        if self.is_blank() {
            return None;
        }
        match self.node_type {
            NodeType::Parent => {
                if let Some(node) = &self.node {
                    Some(node.parent_hash.clone())
                } else {
                    None
                }
            }
            NodeType::Leaf => {
                if let Some(key_package) = &self.key_package {
                    let parent_hash_extension =
                        key_package.extension_with_type(ExtensionType::ParentHash);
                    match parent_hash_extension {
                        Some(phe) => {
                            let phe = match phe.to_parent_hash_extension() {
                                Ok(phe) => phe,
                                Err(_) => return None,
                            };
                            Some(phe.parent_hash().to_vec())
                        }
                        None => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Get a reference to the key package in this node.
    pub fn key_package(&self) -> Option<&KeyPackage> {
        self.key_package.as_ref()
    }

    /// Get a mutable reference to the key package in this node.
    pub(crate) fn key_package_mut(&mut self) -> Option<&mut KeyPackage> {
        self.key_package.as_mut()
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ParentNode {
    public_key: HPKEPublicKey,
    unmerged_leaves: Vec<u32>,
    parent_hash: Vec<u8>,
}

impl ParentNode {
    pub fn new(public_key: HPKEPublicKey, unmerged_leaves: &[u32], parent_hash: &[u8]) -> Self {
        Self {
            public_key,
            unmerged_leaves: unmerged_leaves.to_vec(),
            parent_hash: parent_hash.to_vec(),
        }
    }
    pub fn public_key(&self) -> &HPKEPublicKey {
        &self.public_key
    }
    pub fn set_parent_hash(&mut self, hash: Vec<u8>) {
        self.parent_hash = hash;
    }
    pub fn unmerged_leaves(&self) -> &[u32] {
        &self.unmerged_leaves
    }
    pub fn unmerged_leaves_mut(&mut self) -> &mut Vec<u32> {
        &mut self.unmerged_leaves
    }
}

impl Codec for ParentNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.public_key.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.unmerged_leaves)?;
        encode_vec(VecSize::VecU8, buffer, &self.parent_hash)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = HPKEPublicKey::decode(cursor)?;
        let unmerged_leaves = decode_vec(VecSize::VecU32, cursor)?;
        let parent_hash = decode_vec(VecSize::VecU8, cursor)?;
        Ok(ParentNode {
            public_key,
            unmerged_leaves,
            parent_hash,
        })
    }
}
