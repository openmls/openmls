use crate::ciphersuite::*;
use crate::codec::*;
use crate::extensions::*;
use crate::key_packages::*;

#[derive(PartialEq, Clone, Copy, Debug)]
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

#[allow(dead_code)]
#[derive(Debug, PartialEq, Clone)]
pub(crate) enum NodeContents {
    LeafContents(KeyPackage),
    ParentContents(ParentNode),
}

#[derive(Debug, PartialEq, Clone)]
pub struct ParentNode {
    public_key: HPKEPublicKey,
    unmerged_leaves: Vec<u32>,
    parent_hash: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
/// Nodes without contents are blanks.
pub struct Node {
    pub(crate) node_type: NodeType,
    pub(crate) node_contents: Option<NodeContents>,
}

#[allow(dead_code)]
impl Node {
    pub(crate) fn new_leaf(contents_option: Option<NodeContents>) -> Self {
        Node {
            node_type: NodeType::Leaf,
            node_contents: contents_option,
        }
    }
    pub fn new_blank_parent_node() -> Self {
        Node {
            node_type: NodeType::Parent,
            node_contents: None,
        }
    }
    pub fn public_key(&self) -> Option<&HPKEPublicKey> {
        match (self.node_type, &self.node_contents) {
            (NodeType::Leaf, None) => None,
            (NodeType::Leaf, Some(NodeContents::LeafContents(key_package))) => {
                Some(key_package.hpke_init_key())
            }
            (NodeType::Parent, Some(NodeContents::ParentContents(parent_node))) => {
                Some(&parent_node.public_key())
            }
            _ => None,
        }
    }

    /// Turn a node into a blank.
    pub fn blank(&mut self) {
        self.node_contents = None;
    }

    pub fn is_blank(&self) -> bool {
        self.node_contents.is_none()
    }

    pub fn hash(&self, ciphersuite: &Ciphersuite) -> Option<Vec<u8>> {
        if let Some(NodeContents::ParentContents(parent_node)) = &self.node_contents {
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
        match (self.node_type, &self.node_contents) {
            (NodeType::Parent, Some(NodeContents::ParentContents(parent_node))) => {
                Some(parent_node.parent_hash.clone())
            }
            (NodeType::Leaf, Some(NodeContents::LeafContents(key_package))) => {
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
            }
            _ => None,
        }
    }
}

#[allow(dead_code)]
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
    pub fn parent_hash(&self) -> &[u8] {
        &self.parent_hash
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
