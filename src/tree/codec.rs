use tls_codec::TlsSize;

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

impl tls_codec::TlsSize for ParentNode {
    #[inline]
    fn serialized_len(&self) -> usize {
        self.public_key.serialized_len()
            + 4
            + self.unmerged_leaves.len() * 4
            + 1
            + self.parent_hash.len()
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

impl<'a> tls_codec::Serialize for ParentHashInput<'a> {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), tls_codec::Error> {
        debug_assert!(buffer.capacity() == (buffer.len() + self.serialized_len()));
        self.public_key.tls_serialize(buffer)?;
        buffer.push(self.parent_hash.len() as u8);
        buffer.extend_from_slice(&self.parent_hash);
        buffer.extend_from_slice(&(self.original_child_resolution.len() as u32).to_be_bytes());
        for &pk in self.original_child_resolution.iter() {
            pk.tls_serialize(buffer)?;
        }
        debug_assert!(buffer.capacity() == buffer.len());
        Ok(())
    }
}

impl<'a> tls_codec::TlsSize for ParentHashInput<'a> {
    #[inline]
    fn serialized_len(&self) -> usize {
        self.public_key.serialized_len()
            + 1
            + self.parent_hash.len()
            + 4
            + self
                .original_child_resolution
                .iter()
                .fold(0, |acc, e| acc + e.serialized_len())
    }
}

impl<'a> tls_codec::Serialize for ParentNodeTreeHashInput<'a> {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), tls_codec::Error> {
        debug_assert!(buffer.capacity() == (buffer.len() + self.serialized_len()));
        buffer.extend_from_slice(&self.node_index.to_be_bytes());
        self.parent_node
            .encode(buffer)
            .map_err(|_| tls_codec::Error::EncodingError)?;
        buffer.push(self.left_hash.len() as u8);
        buffer.extend_from_slice(&self.left_hash);
        buffer.push(self.right_hash.len() as u8);
        buffer.extend_from_slice(&self.right_hash);
        debug_assert!(buffer.capacity() == buffer.len());
        Ok(())
    }
}

impl<'a> tls_codec::TlsSize for ParentNodeTreeHashInput<'a> {
    #[inline]
    fn serialized_len(&self) -> usize {
        4 + self.parent_node.serialized_len() + 1 + self.left_hash.len() + 1 + self.right_hash.len()
    }
}

impl<'a> tls_codec::Serialize for LeafNodeHashInput<'a> {
    fn tls_serialize(&self, buffer: &mut Vec<u8>) -> Result<(), tls_codec::Error> {
        debug_assert!(buffer.capacity() == (buffer.len() + self.serialized_len()));
        buffer.extend_from_slice(&self.node_index.as_u32().to_be_bytes());
        self.key_package
            .encode(buffer)
            .map_err(|_| tls_codec::Error::EncodingError)?;
        debug_assert!(buffer.capacity() == buffer.len());
        Ok(())
    }
}

impl<'a> tls_codec::TlsSize for LeafNodeHashInput<'a> {
    #[inline]
    fn serialized_len(&self) -> usize {
        4 + self.key_package.serialized_len()
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
