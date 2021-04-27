use crate::tree::{node::*, secret_tree::*, *};
use std::convert::TryFrom;

// Nodes

impl Codec for NodeType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        match NodeType::try_from(u8::decode(cursor)?) {
            Ok(node_type) => Ok(node_type),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

impl Codec for Node {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_type.encode(buffer)?;
        match self.node_type {
            NodeType::Leaf => {
                self.key_package.as_ref().unwrap().encode(buffer)?;
            }
            NodeType::Parent => {
                self.node.as_ref().unwrap().encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let node_type = NodeType::decode(cursor)?;
        let (key_package, node) = match node_type {
            NodeType::Leaf => (Some(KeyPackage::decode(cursor)?), None),
            NodeType::Parent => (None, Some(ParentNode::decode(cursor)?)),
        };
        Ok(Node {
            node_type,
            key_package,
            node,
        })
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

impl Codec for UpdatePathNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.public_key.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.encrypted_path_secret)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = HPKEPublicKey::decode(cursor)?;
        let encrypted_path_secret = decode_vec(VecSize::VecU32, cursor)?;
        Ok(UpdatePathNode {
            public_key,
            encrypted_path_secret,
        })
    }
}

impl Codec for UpdatePath {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.leaf_key_package.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.nodes)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let leaf_key_package = KeyPackage::decode(cursor)?;
        let nodes = decode_vec(VecSize::VecU32, cursor)?;
        Ok(UpdatePath {
            leaf_key_package,
            nodes,
        })
    }
}

// ASTree Codecs

impl Codec for SecretTreeNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.secret.encode(buffer)?;
        Ok(())
    }
}

// Hash inputs

impl<'a> Codec for ParentHashInput<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.public_key.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.parent_hash)?;
        encode_vec(VecSize::VecU32, buffer, &self.original_child_resolution)?;
        Ok(())
    }
}

impl<'a> Codec for ParentNodeTreeHashInput<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_index.encode(buffer)?;
        self.parent_node.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.left_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.right_hash)?;
        Ok(())
    }
}

impl<'a> Codec for LeafNodeHashInput<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_index.as_u32().encode(buffer)?;
        self.key_package.encode(buffer)?;
        Ok(())
    }
}

// Index

impl Codec for LeafIndex {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.0.encode(buffer)
    }
}

// Secret tree

impl Codec for TreeContext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node.encode(buffer)?;
        self.generation.encode(buffer)?;
        Ok(())
    }
}
