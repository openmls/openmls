use crate::tree::{astree::*, node::*, *};

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
        self.kpb.encode(buffer)?;
        self.node_index.as_u32().encode(buffer)?;
        self.path_keypairs.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let kpb = KeyPackageBundle::decode(cursor)?;
        let node_index = NodeIndex::from(u32::decode(cursor)?);
        let path_keypairs = PathKeypairs::decode(cursor)?;
        Ok(OwnLeaf {
            kpb,
            node_index,
            path_keypairs,
        })
    }
}

impl Codec for RatchetTree {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        encode_vec(VecSize::VecU32, buffer, &self.nodes)?;
        self.own_leaf.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<RatchetTree, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let nodes = decode_vec(VecSize::VecU32, cursor)?;
        let own_leaf = OwnLeaf::decode(cursor)?;
        Ok(RatchetTree {
            ciphersuite,
            nodes,
            own_leaf,
        })
    }
}

impl<'a> Codec for ParentNodeHashInput<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_index.encode(buffer)?;
        self.parent_node.encode(buffer)?;
        encode_vec(VecSize::VecU8, buffer, &self.left_hash)?;
        encode_vec(VecSize::VecU8, buffer, &self.right_hash)?;
        Ok(())
    }
    fn decode(_cursor: &mut Cursor) -> Result<Self, CodecError> {
        unimplemented!()
    }
}

impl<'a> Codec for LeafNodeHashInput<'a> {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.node_index.as_u32().encode(buffer)?;
        self.key_package.encode(buffer)?;
        Ok(())
    }
    fn decode(_cursor: &mut Cursor) -> Result<Self, CodecError> {
        unimplemented!()
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
