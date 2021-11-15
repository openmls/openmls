use tls_codec::{Size, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use openmls_traits::{crypto::OpenMlsCrypto, types::HpkeCiphertext};
pub(crate) use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePublicKey},
    prelude::KeyPackage,
};

use super::{
    node::parent_node::{ParentNode, PlainUpdatePathNode},
    TreeSync, TreeSyncDiffError,
};

impl TreeSync {
    pub(crate) fn encrypt_path(
        &self,
        backend: &impl OpenMlsCrypto,
        ciphersuite: &Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &[LeafIndex],
    ) -> Result<UpdatePath, TreeKemError> {
        let copath_resolutions = self
            .empty_diff()
            .copath_resolutions(self.own_leaf_index, exclusion_list)?;
        // Make sure that the lists have the same length.
        if path.len() != copath_resolutions.len() {
            return Err(TreeKemError::PathLengthError);
        }

        // TODO: Implement .encrypt() for UpdatePathNode and use it here.

        // Encrypt the secrets
        //let mut ciphertexts = Vec::new();
        for (node, resolution) in path.iter().zip(copath_resolutions.iter()) {
            //let mut node_ciphertexts = Vec::new();
            //for pk in resolution {
            //    backend.hpke_seal(
            //        ciphersuite.hpke_config(),
            //        pk.as_slice(),
            //        group_context,
            //        &[],
            //        ,
            //    )
            //}
        }

        todo!()
    }
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     HPKEPublicKey public_key;
///     HPKECiphertext encrypted_path_secret<0..2^32-1>;
/// } UpdatePathNode;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct UpdatePathNode {
    pub(crate) public_key: HpkePublicKey,
    pub(crate) encrypted_path_secret: TlsVecU32<HpkeCiphertext>,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     KeyPackage leaf_key_package;
///     UpdatePathNode nodes<0..2^32-1>;
/// } UpdatePath;
/// ```
#[derive(
    Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct UpdatePath {
    pub(crate) leaf_key_package: KeyPackage,
    pub(crate) nodes: TlsVecU32<UpdatePathNode>,
}

impl UpdatePath {
    /// Create a new update path.
    fn new(leaf_key_package: KeyPackage, nodes: Vec<UpdatePathNode>) -> Self {
        Self {
            leaf_key_package,
            nodes: nodes.into(),
        }
    }
}

implement_error! {
    pub enum TreeKemError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
            PathLengthError = "The given path to encrypt does not have the same length as the direct path.",
        }
        Complex {
            TreeSyncError(TreeSyncDiffError) = "Error while retrieving public keys from the tree.",
        }
    }
}
