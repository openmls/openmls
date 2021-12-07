use std::collections::HashSet;

use tls_codec::{Error as TlsCodecError, TlsDeserialize, TlsSerialize, TlsSize, TlsVecU32};

use openmls_traits::{crypto::OpenMlsCrypto, types::HpkeCiphertext, OpenMlsCryptoProvider};
pub(crate) use serde::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafIndex,
    ciphersuite::{Ciphersuite, HpkePublicKey},
    messages::{
        proposals::AddProposal, EncryptedGroupSecrets, GroupSecrets, PathSecret, PathSecretError,
    },
    prelude::{KeyPackage, KeyPackageError, ProtocolVersion},
    schedule::{CommitSecret, JoinerSecret, PreSharedKeys},
};

use super::{
    diff::TreeSyncDiff,
    node::parent_node::{ParentNode, ParentNodeError, PlainUpdatePathNode},
    TreeSyncDiffError, TreeSyncError,
};

impl<'a> TreeSyncDiff<'a> {
    pub(crate) fn encrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &HashSet<&LeafIndex>,
        key_package: &KeyPackage,
    ) -> Result<UpdatePath, TreeKemError> {
        let copath_resolutions = self.copath_resolutions(self.own_leaf_index(), exclusion_list)?;

        let mut update_path_nodes = Vec::new();
        // Encrypt the secrets
        for (node, resolution) in path.iter().zip(copath_resolutions.iter()) {
            let update_path_node = node.encrypt(backend, ciphersuite, resolution, group_context);
            update_path_nodes.push(update_path_node);
        }

        Ok(UpdatePath {
            leaf_key_package: key_package.clone(),
            nodes: update_path_nodes.into(),
        })
    }

    /// The path returned here already includes any path secrets included in the
    /// `UpdatePath`.
    pub(crate) fn decrypt_path(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &'static Ciphersuite,
        version: ProtocolVersion,
        update_path: &UpdatePath,
        sender_leaf_index: LeafIndex,
        exclusion_list: &HashSet<&LeafIndex>,
        group_context: &[u8],
    ) -> Result<(Vec<ParentNode>, CommitSecret), TreeKemError> {
        let path_position = self.subtree_root_position(sender_leaf_index, self.own_leaf_index())?;
        let update_path_node = update_path
            .nodes()
            .get(path_position)
            .ok_or(TreeKemError::UpdatePathNodeNotFound)?;

        let (decryption_key, resolution_position) =
            self.decryption_key(sender_leaf_index, exclusion_list)?;
        let ciphertext = match update_path_node.get_encrypted_ciphertext(resolution_position) {
            Some(ct) => ct,
            None => {
                return Err(TreeKemError::EncryptedCiphertextNotFound);
            }
        };

        let path_secret = PathSecret::decrypt(
            backend,
            ciphersuite,
            version,
            ciphertext,
            decryption_key,
            group_context,
        )?;

        let remaining_path_length = update_path.nodes().len() - path_position;
        let (mut derived_path, _plain_update_path, commit_secret) =
            ParentNode::derive_path(backend, ciphersuite, path_secret, remaining_path_length)?;
        // We now check that the public keys in the update path an in the
        // derived path match up.
        for (update_parent_node, derived_parent_node) in update_path
            .nodes()
            .iter()
            .skip(path_position)
            .zip(derived_path.iter())
        {
            if update_parent_node.public_key() != derived_parent_node.public_key() {
                return Err(TreeKemError::PathMismatch);
            }
        }

        // Finally, we append the derived path to the part of the update path
        // below the first node that we have a private key for.
        let mut path: Vec<ParentNode> = update_path
            .nodes()
            .iter()
            .take(path_position)
            .map(|update_path_node| update_path_node.public_key().clone().into())
            .collect();
        path.append(&mut derived_path);

        debug_assert_eq!(path.len(), update_path.nodes().len());

        Ok((path, commit_secret))
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
    pub(crate) encrypted_path_secrets: TlsVecU32<HpkeCiphertext>,
}

impl UpdatePathNode {
    fn get_encrypted_ciphertext(&self, ciphertext_index: usize) -> Option<&HpkeCiphertext> {
        self.encrypted_path_secrets.get(ciphertext_index)
    }

    fn public_key(&self) -> &HpkePublicKey {
        &self.public_key
    }
}

/// Helper struct holding values that are encryptedin the
/// `EncryptedGroupSecrets`. In particular, the `group_secrets_bytes` are
/// encrypted for the `public_key` into `encrypted_group_secrets` later.
pub(crate) struct PlaintextSecret {
    public_key: HpkePublicKey,
    group_secrets_bytes: Vec<u8>,
    key_package_hash: Vec<u8>,
}

impl PlaintextSecret {
    /// Prepare the `GroupSecrets` for a number of `invited_members` based on a
    /// `TreeSyncDiff`. If a slice of [`PlainUpdatePathNode`] is given, they are
    /// included in the [`GroupSecrets`] of the path.
    pub(crate) fn from_plain_update_path(
        diff: &TreeSyncDiff,
        joiner_secret: &JoinerSecret,
        invited_members: Vec<(LeafIndex, AddProposal)>,
        plain_path_option: Option<&[PlainUpdatePathNode]>,
        presharedkeys: &PreSharedKeys,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<Self>, TreeKemError> {
        let mut plaintext_secrets = vec![];
        for (leaf_index, add_proposal) in invited_members {
            let key_package = add_proposal.key_package;
            let key_package_hash = key_package.hash(backend)?;

            let direct_path_position =
                diff.subtree_root_position(diff.own_leaf_index(), leaf_index)?;

            // If a plain path was given, there have to be secrets for every new member.
            let path_secret_option = if let Some(plain_path) = plain_path_option {
                Some(
                    plain_path
                        .get(direct_path_position)
                        .map(|pupn| pupn.path_secret())
                        .ok_or(TreeKemError::PathSecretNotFound)?,
                )
            } else {
                None
            };

            // Create the GroupSecrets object for the respective member.
            let group_secrets_bytes =
                GroupSecrets::new_encoded(joiner_secret, path_secret_option, presharedkeys)?;
            plaintext_secrets.push(PlaintextSecret {
                public_key: key_package.hpke_init_key().clone(),
                group_secrets_bytes,
                key_package_hash,
            });
        }
        Ok(plaintext_secrets)
    }

    pub(crate) fn encrypt(
        self,
        backend: &impl OpenMlsCryptoProvider,
        ciphersuite: &Ciphersuite,
    ) -> EncryptedGroupSecrets {
        let encrypted_group_secrets = backend.crypto().hpke_seal(
            ciphersuite.hpke_config(),
            self.public_key.as_slice(),
            &[],
            &[],
            &self.group_secrets_bytes,
        );
        EncryptedGroupSecrets {
            key_package_hash: self.key_package_hash.into(),
            encrypted_group_secrets,
        }
    }
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
    leaf_key_package: KeyPackage,
    nodes: TlsVecU32<UpdatePathNode>,
}

impl UpdatePath {
    pub(crate) fn nodes(&self) -> &TlsVecU32<UpdatePathNode> {
        &self.nodes
    }

    pub(crate) fn leaf_key_package(&self) -> &KeyPackage {
        &self.leaf_key_package
    }

    #[cfg(test)]
    pub fn new(leaf_key_package: KeyPackage, nodes: TlsVecU32<UpdatePathNode>) -> Self {
        Self {
            leaf_key_package,
            nodes,
        }
    }
}

implement_error! {
    pub enum TreeKemError {
        Simple {
            LibraryError = "An inconsistency in the internal state of the tree was detected.",
            PathLengthError = "The given path to encrypt does not have the same length as the direct path.",
            PathMismatch = "The received update path and the derived nodes are inconsistent.",
            UpdatePathNodeNotFound = "Couldn't find our UpdatePathNode in the given UpdatePath.",
            EncryptedCiphertextNotFound = "Couldn't find a matching encrypted ciphertext in the given UpdatePathNode.",
            PathSecretNotFound = "Couldn't find the path secret to encrypt for one of the new members.",
        }
        Complex {
            TreeSyncError(TreeSyncError) = "Error while creating treesync diff.",
            TreeSyncDiffError(TreeSyncDiffError) = "Error while retrieving public keys from the tree.",
            PathSecretError(PathSecretError) = "Error decrypting PathSecret.",
            PathDerivationError(ParentNodeError) = "Error deriving path from PathSecret.",
            EncodingError(TlsCodecError) = "Error while encoding GroupSecrets.",
            KeyPackageError(KeyPackageError) = "Error while hashing KeyPackage.",
        }
    }
}
