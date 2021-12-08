//! This module contains helper structs and functions related to parent hashing
//! and tree hashing.
use openmls_traits::{types::CryptoError, OpenMlsCryptoProvider};
use tls_codec::{
    Error as TlsCodecError, Serialize, TlsSerialize, TlsSize, TlsSliceU32, TlsSliceU8,
};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePublicKey},
};

use super::node::parent_node::ParentNode;
use crate::key_packages::KeyPackage;

/// Helper struct that can be serialized in the course of parent hash
/// computation.
#[derive(TlsSerialize, TlsSize)]
pub(super) struct ParentHashInput<'a> {
    public_key: &'a HpkePublicKey,
    parent_hash: TlsSliceU8<'a, u8>,
    original_child_resolution: TlsSliceU32<'a, HpkePublicKey>,
}

impl<'a> ParentHashInput<'a> {
    /// Create a new [`ParentHashInput`] instance.
    pub(super) fn new(
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

    /// Serialize and hash this instance of [`ParentHashInput`].
    pub(super) fn hash(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> Result<Vec<u8>, ParentHashError> {
        let payload = self.tls_serialize_detached()?;
        Ok(ciphersuite.hash(backend, &payload)?)
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
            HashError(CryptoError) = "Error while hashing payload.",
        }
    }
}

/// Helper struct that can be serialized in the course of tree hash computation.
#[derive(TlsSerialize, TlsSize)]
pub struct LeafNodeHashInput<'a> {
    pub(super) leaf_index: &'a LeafIndex,
    pub(super) key_package: Option<&'a KeyPackage>,
}

impl<'a> LeafNodeHashInput<'a> {
    /// Create a new [`LeafNodeHashInput`] instance.
    pub(super) fn new(leaf_index: &'a LeafIndex, key_package: Option<&'a KeyPackage>) -> Self {
        Self {
            leaf_index,
            key_package,
        }
    }

    /// Serialize and hash this instance of [`LeafNodeHashInput`].
    pub(super) fn hash(
        &self,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<u8>, CryptoError> {
        let payload = self.tls_serialize_detached().unwrap();
        ciphersuite.hash(backend, &payload)
    }
}

/// Helper struct that can be serialized in the course of tree hash computation.
#[derive(TlsSerialize, TlsSize)]
pub(super) struct ParentNodeTreeHashInput<'a> {
    node_index: LeafIndex,
    parent_node: Option<&'a ParentNode>,
    left_hash: TlsSliceU8<'a, u8>,
    right_hash: TlsSliceU8<'a, u8>,
}

impl<'a> ParentNodeTreeHashInput<'a> {
    /// Create a new [`ParentNodeTreeHashInput`] instance.
    pub(super) fn new(
        node_index: LeafIndex,
        parent_node: Option<&'a ParentNode>,
        left_hash: TlsSliceU8<'a, u8>,
        right_hash: TlsSliceU8<'a, u8>,
    ) -> Self {
        Self {
            node_index,
            parent_node,
            left_hash,
            right_hash,
        }
    }

    /// Serialize and hash this instance of [`ParentNodeTreeHashInput`].
    pub(super) fn hash(
        &self,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<u8>, CryptoError> {
        let payload = self.tls_serialize_detached().unwrap();
        ciphersuite.hash(backend, &payload)
    }
}
