//! This module contains the [`ParentNode`] struct, its implementation, as well
//! as the [`PlainUpdatePathNode`], a helper struct for the creation of
//! [`UpdatePathNode`] instances.
use serde::{Deserialize, Serialize};
use thiserror::*;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize, VLBytes};

use super::encryption_keys::EncryptionKey;
use crate::binary_tree::array_representation::LeafNodeIndex;

/// This struct implements the MLS parent node. It contains its public key,
/// parent hash and unmerged leaves. Additionally, it may contain the private
/// key corresponding to the public key.
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct ParentNode {
    pub(super) encryption_key: EncryptionKey,
    pub(super) parent_hash: VLBytes,
    pub(super) unmerged_leaves: UnmergedLeaves,
}

/// A helper struct that maintains a sorted list of unmerged leaves.
#[derive(Debug, Eq, PartialEq, Clone, Serialize, Deserialize, TlsSize, TlsSerialize)]
pub(in crate::treesync) struct UnmergedLeaves {
    list: Vec<LeafNodeIndex>,
}

#[derive(Error, Debug)]
pub(in crate::treesync) enum UnmergedLeavesError {
    /// The list of leaves is not sorted.
    #[error("The list of leaves is not sorted.")]
    NotSorted,
}

impl TryFrom<Vec<LeafNodeIndex>> for UnmergedLeaves {
    type Error = UnmergedLeavesError;

    fn try_from(list: Vec<LeafNodeIndex>) -> Result<Self, Self::Error> {
        // The list of unmerged leaves must be sorted.
        if !list.windows(2).all(|e| e[0] < e[1]) {
            return Err(UnmergedLeavesError::NotSorted);
        }
        Ok(Self { list })
    }
}
