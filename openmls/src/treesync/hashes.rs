//! This module contains helper structs and functions related to parent hashing
//! and tree hashing.
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use tls_codec::{Serialize, TlsSerialize, TlsSize, VLByteSlice};

use crate::{
    binary_tree::array_representation::LeafNodeIndex, ciphersuite::HpkePublicKey,
    error::LibraryError,
};

use super::{node::parent_node::ParentNode, LeafNode};

/// Helper struct that can be serialized in the course of parent hash
/// computation.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
/// HPKEPublicKey encryption_key;
///     opaque parent_hash<V>;
///     opaque original_sibling_tree_hash<V>;
/// } ParentHashInput;
/// ```
#[derive(TlsSerialize, TlsSize)]
pub(super) struct ParentHashInput<'a> {
    public_key: &'a HpkePublicKey,
    parent_hash: VLByteSlice<'a>,
    original_sibling_tree_hash: VLByteSlice<'a>,
}

impl<'a> ParentHashInput<'a> {
    /// Create a new [`ParentHashInput`] instance.
    pub(super) fn new(
        public_key: &'a HpkePublicKey,
        parent_hash: &'a [u8],
        original_sibling_tree_hash: &'a [u8],
    ) -> Self {
        Self {
            public_key,
            parent_hash: VLByteSlice(parent_hash),
            original_sibling_tree_hash: VLByteSlice(original_sibling_tree_hash),
        }
    }

    /// Serialize and hash this instance of [`ParentHashInput`].
    pub(super) fn hash(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Vec<u8>, LibraryError> {
        let payload = self
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        crypto
            .hash(ciphersuite.hash_algorithm(), &payload)
            .map_err(LibraryError::unexpected_crypto_error)
    }
}

/// Helper struct that can be serialized in the course of tree hash computation.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// enum {
///     reserved(0),
///     leaf(1),
///     parent(2),
///     (255)
/// } NodeType;
/// ```
#[derive(TlsSerialize, TlsSize)]
#[repr(u8)]
enum NodeType<'a> {
    #[tls_codec(discriminant = 1)]
    Leaf(LeafNodeHashInput<'a>),
    #[tls_codec(discriminant = 2)]
    Parent(ParentNodeHashInput<'a>),
}

/// Helper struct that can be serialized in the course of tree hash computation.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///   NodeType node_type;
/// select (TreeHashInput.node_type) {
///     case leaf:   LeafNodeHashInput leaf_node;
///     case parent: ParentNodeHashInput parent_node;
///   }
/// } TreeHashInput;
/// ```
#[derive(TlsSerialize, TlsSize)]
pub(super) struct TreeHashInput<'a> {
    node_type: NodeType<'a>,
}

impl<'a> TreeHashInput<'a> {
    /// Create a new [`TreeHashInput`] instance from a leaf node.
    pub(super) fn new_leaf(leaf_index: &'a LeafNodeIndex, leaf_node: Option<&'a LeafNode>) -> Self {
        Self {
            node_type: NodeType::Leaf(LeafNodeHashInput {
                leaf_index,
                leaf_node,
            }),
        }
    }

    /// Create a new [`TreeHashInput`] instance from a parent node.
    pub(super) fn new_parent(
        parent_node: Option<&'a ParentNode>,
        left_hash: VLByteSlice<'a>,
        right_hash: VLByteSlice<'a>,
    ) -> Self {
        Self {
            node_type: NodeType::Parent(ParentNodeHashInput {
                parent_node,
                left_hash,
                right_hash,
            }),
        }
    }

    /// Serialize and hash this instance of [`TreeHashInput`].
    pub(super) fn hash(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Vec<u8>, LibraryError> {
        let payload = self
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        crypto
            .hash(ciphersuite.hash_algorithm(), &payload)
            .map_err(LibraryError::unexpected_crypto_error)
    }
}

/// Helper struct that can be serialized in the course of tree hash computation.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     uint32 leaf_index;
///     optional<LeafNode> leaf_node;
/// } LeafNodeHashInput;
/// ```
#[derive(TlsSerialize, TlsSize)]
struct LeafNodeHashInput<'a> {
    leaf_index: &'a LeafNodeIndex,
    leaf_node: Option<&'a LeafNode>,
}

/// Helper struct that can be serialized in the course of tree hash computation.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     optional<ParentNode> parent_node;
///     opaque left_hash<V>;
///     opaque right_hash<V>;
/// } ParentNodeHashInput;
/// ```
#[derive(TlsSerialize, TlsSize)]
struct ParentNodeHashInput<'a> {
    parent_node: Option<&'a ParentNode>,
    left_hash: VLByteSlice<'a>,
    right_hash: VLByteSlice<'a>,
}
