use std::collections::HashSet;

use openmls_traits::types::Ciphersuite;
use openmls_traits::{key_store::OpenMlsKeyStore, signatures::Signer, OpenMlsCryptoProvider};
use tls_codec::Serialize;

use crate::prelude::{Capabilities, CredentialType, ProtocolVersion};
use crate::{
    binary_tree::LeafNodeIndex,
    credentials::CredentialWithKey,
    error::LibraryError,
    extensions::Extensions,
    group::{
        config::CryptoConfig, core_group::create_commit_params::CommitType,
        errors::CreateCommitError,
    },
    key_packages::{KeyPackage, KeyPackageSecretEncapsulation},
    schedule::CommitSecret,
    treesync::{
        node::{
            encryption_keys::EncryptionKeyPair, leaf_node::LeafNode,
            parent_node::PlainUpdatePathNode,
        },
        treekem::UpdatePath,
    },
};

use super::PublicGroupDiff;

/// A helper struct which contains the values resulting from the preparation of
/// a commit with path.
#[derive(Default)]
pub(crate) struct PathComputationResult {
    pub(crate) commit_secret: Option<CommitSecret>,
    pub(crate) encrypted_path: Option<UpdatePath>,
    pub(crate) plain_path: Option<Vec<PlainUpdatePathNode>>,
    pub(crate) new_keypairs: Vec<EncryptionKeyPair>,
}

impl PublicGroupDiff<'_> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn compute_path<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        leaf_index: LeafNodeIndex,
        mut leaf_node: Option<LeafNode>,
        exclusion_list: HashSet<&LeafNodeIndex>,
        commit_type: CommitType,
        signer: &impl Signer,
        credential_with_key: Option<CredentialWithKey>,
        extensions: Option<&Extensions>,
    ) -> Result<PathComputationResult, CreateCommitError<KeyStore::Error>> {
        let version = self.group_context().protocol_version();
        let ciphersuite = self.group_context().ciphersuite();
        let group_id = self.group_context().group_id().clone();

        let mut new_keypairs = if commit_type == CommitType::External {
            // If this is an external commit we add a fresh leaf to the diff.
            // Generate a KeyPackageBundle to generate a payload from for later
            // path generation.
            let KeyPackageSecretEncapsulation {
                key_package,
                encryption_keypair,
                // The KeyPackage is immediately put into the group. No need for
                // the init key.
                init_private_key: _,
            } = KeyPackage::builder()
                .leaf_node_capabilities(
                    // TODO: factorize & have this injected by client
                    Capabilities::new(
                        Some(&[ProtocolVersion::Mls10]),
                        Some(&[
                            Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                            Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256,
                            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                            Ciphersuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384,
                            Ciphersuite::MLS_256_DHKEMP521_AES256GCM_SHA512_P521,
                        ]),
                        Some(&[]),
                        Some(&[]),
                        Some(&[CredentialType::Basic, CredentialType::X509]),
                    ),
                )
                .build_without_key_storage(
                    CryptoConfig {
                        ciphersuite,
                        version,
                    },
                    backend,
                    signer,
                    credential_with_key.ok_or(CreateCommitError::MissingCredential)?,
                )?;

            let leaf_node: LeafNode = key_package.into();
            self.diff
                .add_leaf(leaf_node)
                .map_err(|_| LibraryError::custom("Tree full: cannot add more members"))?;
            vec![encryption_keypair]
        } else {
            // When we update with an explicit leaf_node consider it (instead of the old one) when computing the UpdatePath
            if let Some(leaf_node) = leaf_node.take() {
                self.diff.update_leaf(leaf_node, leaf_index)
            }

            // If we're already in the tree, we rekey our existing leaf.
            let own_diff_leaf = self
                .diff
                .leaf_mut(leaf_index)
                .ok_or_else(|| LibraryError::custom("Unable to get own leaf from diff"))?;

            let encryption_keypair = own_diff_leaf.rekey(
                &group_id,
                leaf_index,
                None,
                ciphersuite,
                version,
                backend,
                signer,
            )?;
            vec![encryption_keypair]
        };

        // Derive and apply an update path based on the previously
        // generated new leaf.
        let (plain_path, mut new_parent_keypairs, commit_secret) = self
            .diff
            .apply_own_update_path(backend, signer, ciphersuite, group_id, leaf_index)?;

        new_keypairs.append(&mut new_parent_keypairs);

        // After we've processed the path, we can update the group context s.t.
        // the updated group context is used for path secret encryption. Note
        // that we have not yet updated the confirmed transcript hash.
        self.update_group_context(backend, extensions.cloned())?;

        let serialized_group_context = self
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        // Encrypt the path to the correct recipient nodes.
        let encrypted_path = self.diff.encrypt_path(
            backend,
            ciphersuite,
            &plain_path,
            &serialized_group_context,
            &exclusion_list,
            leaf_index,
        )?;
        let leaf_node = self
            .diff
            .leaf(leaf_index)
            .ok_or_else(|| LibraryError::custom("Couldn't find own leaf"))?
            .clone();
        let encrypted_path = UpdatePath::new(leaf_node, encrypted_path);
        Ok(PathComputationResult {
            commit_secret: Some(commit_secret),
            encrypted_path: Some(encrypted_path),
            plain_path: Some(plain_path),
            new_keypairs,
        })
    }
}
