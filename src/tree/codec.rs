use crate::tree::astree::*;
use crate::tree::*;

impl Codec for NodeType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(NodeType::from(u8::decode(cursor)?))
    }
}

impl Codec for Node {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_type.encode(buffer)?;
        self.key_package.encode(buffer)?;
        self.node.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let node_type = NodeType::decode(cursor)?;
        let key_package = Option::<KeyPackage>::decode(cursor)?;
        let node = Option::<ParentNode>::decode(cursor)?;
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

impl Codec for PathKeypairs {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU32, buffer, &self.keypairs)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let keypairs = decode_vec(VecSize::VecU32, cursor)?;
        Ok(PathKeypairs { keypairs })
    }
}

impl Codec for OwnLeaf {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        self.kpb.encode(buffer)?;
        self.leaf_index.as_u32().encode(buffer)?;
        self.path_keypairs.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let kpb = KeyPackageBundle::decode(cursor)?;
        let leaf_index = NodeIndex::from(u32::decode(cursor)?);
        let path_keypairs = PathKeypairs::decode(cursor)?;
        Ok(OwnLeaf {
            ciphersuite,
            kpb,
            leaf_index,
            path_keypairs,
        })
    }
}

impl Codec for Tree {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.nodes)?;
        self.own_leaf.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let nodes = decode_vec(VecSize::VecU32, cursor)?;
        let own_leaf = OwnLeaf::decode(cursor)?;
        Ok(Tree {
            ciphersuite,
            nodes,
            own_leaf,
        })
    }
}

impl Codec for ParentNodeHashInput {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_index.encode(buffer)?;
        self.parent_node.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.left_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.right_hash)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let node_index = u32::decode(cursor)?;
        let parent_node = Option::<ParentNode>::decode(cursor)?;
        let left_hash = decode_vec(VecSize::VecU8, cursor)?;
        let right_hash = decode_vec(VecSize::VecU8, cursor)?;
        Ok(ParentNodeHashInput {
            node_index,
            parent_node,
            left_hash,
            right_hash,
        })
    }
}

impl Codec for LeafNodeHashInput {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_index.as_u32().encode(buffer)?;
        self.key_package.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let node_index = NodeIndex::from(u32::decode(cursor)?);
        let key_package = Option::<KeyPackage>::decode(cursor)?;
        Ok(LeafNodeHashInput {
            node_index,
            key_package,
        })
    }
}

impl Codec for DirectPathNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.public_key.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.encrypted_path_secret)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = HPKEPublicKey::decode(cursor)?;
        let encrypted_path_secret = decode_vec(VecSize::VecU32, cursor)?;
        Ok(DirectPathNode {
            public_key,
            encrypted_path_secret,
        })
    }
}

impl Codec for DirectPath {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.leaf_key_package.encode(buffer)?;
        encode_vec(VecSize::VecU16, buffer, &self.nodes)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let leaf_key_package = KeyPackage::decode(cursor)?;
        let nodes = decode_vec(VecSize::VecU16, cursor)?;
        Ok(DirectPath {
            leaf_key_package,
            nodes,
        })
    }
}

// ASTree Codecs

impl Codec for ASTreeNode {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.secret)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let secret = decode_vec(VecSize::VecU8, cursor)?;
        Ok(ASTreeNode { secret })
    }
}
