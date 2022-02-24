//! This module contains helper structs and functions related to parent hashing
//! and tree hashing.
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsCryptoProvider};
use tls_codec::{Serialize, TlsSerialize, TlsSize, TlsSliceU32, TlsSliceU8};

use crate::{binary_tree::LeafIndex, ciphersuite::HpkePublicKey, error::LibraryError};

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
        ciphersuite: Ciphersuite,
    ) -> Result<Vec<u8>, LibraryError> {
        let payload = self
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        backend
            .crypto()
            .hash(ciphersuite.hash_algorithm(), &payload)
            .map_err(LibraryError::unexpected_crypto_error)
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
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<u8>, LibraryError> {
        let payload = self
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        backend
            .crypto()
            .hash(ciphersuite.hash_algorithm(), &payload)
            .map_err(LibraryError::unexpected_crypto_error)
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
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<u8>, LibraryError> {
        let payload = self
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        backend
            .crypto()
            .hash(ciphersuite.hash_algorithm(), &payload)
            .map_err(LibraryError::unexpected_crypto_error)
    }
}
