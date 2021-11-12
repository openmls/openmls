use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::{
    Error as TlsCodecError, Serialize, Size, TlsSerialize, TlsSize, TlsSliceU32, TlsSliceU8,
};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePublicKey},
};

use super::node::ParentNode;
use crate::key_packages::KeyPackage;

#[derive(TlsSerialize, TlsSize)]
pub(crate) struct ParentHashInput<'a> {
    public_key: &'a HpkePublicKey,
    parent_hash: TlsSliceU8<'a, u8>,
    original_child_resolution: TlsSliceU32<'a, HpkePublicKey>,
}

impl<'a> ParentHashInput<'a> {
    pub(crate) fn new(
        public_key: &'a HpkePublicKey,
        parent_hash: &'a [u8],
        original_child_resolution: &'a [HpkePublicKey],
    ) -> Self {
        Self {
            public_key,
            parent_hash: TlsSliceU8(parent_hash),
            original_child_resolution: TlsSliceU32(original_child_resolution),
        }
    }
    pub(crate) fn hash(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<Vec<u8>, ParentHashError> {
        let payload = self.tls_serialize_detached()?;
        Ok(ciphersuite.hash(backend, &payload))
    }
}

implement_error! {
    pub enum ParentHashError {
        Simple {
            EndedWithLeafNode = "The search for a valid child ended with a leaf node.",
            AllChecksFailed = "All checks failed: Neither child has the right parent hash.",
            InputNotParentNode = "The input node is not a parent node.",
            NotAParentNode = "The node is not a parent node.",
            EmptyParentNode = "The parent node was blank.",
        }
        Complex {
            CodecError(TlsCodecError) = "Error while serializing payload for parent hash.",
        }
    }
}

pub struct LeafNodeHashInput<'a> {
    pub(crate) leaf_index: &'a LeafIndex,
    pub(crate) key_package: Option<&'a KeyPackage>,
}

// FIXME: These explicit implementations shouldn't be necessary.
impl<'a> tls_codec::Size for LeafNodeHashInput<'a> {
    fn tls_serialized_len(&self) -> usize {
        self.leaf_index.tls_serialized_len()
            + match self.key_package {
                Some(kp) => kp.tls_serialized_len(),
                None => {
                    let none: Option<KeyPackage> = None;
                    none.tls_serialized_len()
                }
            }
    }
}

impl<'a> tls_codec::Serialize for LeafNodeHashInput<'a> {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, TlsCodecError> {
        let written = self.leaf_index.tls_serialize(writer)?;
        match self.key_package {
            Some(kp) => kp.tls_serialize(writer),
            None => {
                let none: Option<KeyPackage> = None;
                none.tls_serialize(writer)
            }
        }
        .map(|l| l + written)
    }
}

impl<'a> LeafNodeHashInput<'a> {
    pub(crate) fn new(leaf_index: &'a LeafIndex, key_package: Option<&'a KeyPackage>) -> Self {
        Self {
            leaf_index,
            key_package,
        }
    }
    pub fn hash(&self, ciphersuite: &Ciphersuite, backend: &impl OpenMlsCryptoProvider) -> Vec<u8> {
        let payload = self.tls_serialize_detached().unwrap();
        ciphersuite.hash(backend, &payload)
    }
}

#[derive(TlsSerialize, TlsSize)]
pub struct ParentNodeTreeHashInput<'a> {
    pub(crate) parent_node: Option<&'a ParentNode>,
    pub(crate) left_hash: TlsSliceU8<'a, u8>,
    pub(crate) right_hash: TlsSliceU8<'a, u8>,
}

impl<'a> ParentNodeTreeHashInput<'a> {
    pub(crate) fn new(
        parent_node: Option<&'a ParentNode>,
        left_hash: TlsSliceU8<'a, u8>,
        right_hash: TlsSliceU8<'a, u8>,
    ) -> Self {
        Self {
            parent_node,
            left_hash,
            right_hash,
        }
    }
    pub(crate) fn hash(
        &self,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Vec<u8> {
        let payload = self.tls_serialize_detached().unwrap();
        ciphersuite.hash(backend, &payload)
    }
}
