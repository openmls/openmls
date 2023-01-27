use std::collections::HashSet;

use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};
use tls_codec::Serialize;

use crate::{
    binary_tree::LeafNodeIndex,
    credentials::CredentialBundle,
    group::{config::CryptoConfig, errors::CreateCommitError, CommitType},
    prelude::{KeyPackageCreationResult, LibraryError},
    prelude_test::KeyPackage,
    schedule::CommitSecret,
    treesync::{
        node::{
            encryption_keys::EncryptionKeyPair, leaf_node::OpenMlsLeafNode,
            parent_node::PlainUpdatePathNode,
        },
        treekem::UpdatePath,
    },
};

use super::PublicGroupDiff;

/// A helper struct which contains the values resulting from the preparation of
/// a commit with path.
#[derive(Default)]
pub(crate) struct PathProcessingResult {
    pub(crate) commit_secret: Option<CommitSecret>,
    pub(crate) encrypted_path: Option<UpdatePath>,
    pub(crate) plain_path: Option<Vec<PlainUpdatePathNode>>,
    pub(crate) new_keypairs: Vec<EncryptionKeyPair>,
}

impl<'a> PublicGroupDiff<'a> {
    pub(crate) fn process_path<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        leaf_index: LeafNodeIndex,
        exclusion_list: HashSet<&LeafNodeIndex>,
        commit_type: CommitType,
        credential_bundle: &CredentialBundle,
    ) -> Result<PathProcessingResult, CreateCommitError<KeyStore::Error>> {
        let mut new_keypairs = if commit_type == CommitType::External {
            // If this is an external commit we add a fresh leaf to the diff.
            // Generate a KeyPackageBundle to generate a payload from for later
            // path generation.
            let KeyPackageCreationResult {
                key_package,
                encryption_keypair,
                // The KeyPackage is immediately put into the group. No need for
                // the init key.
                init_private_key: _,
            } = KeyPackage::builder().build_without_key_storage(
                CryptoConfig {
                    ciphersuite: self.original_group.ciphersuite(),
                    version: self.original_group.version(),
                },
                backend,
                credential_bundle,
            )?;

            let mut leaf_node: OpenMlsLeafNode = key_package.into();
            leaf_node.set_leaf_index(leaf_index);
            self.diff
                .add_leaf(leaf_node)
                .map_err(|_| LibraryError::custom("Tree full: cannot add more members"))?;
            vec![encryption_keypair]
        } else {
            // If we're already in the tree, we rekey our existing leaf.
            let own_diff_leaf = self
                .diff
                .leaf_mut(leaf_index)
                .ok_or_else(|| LibraryError::custom("Unable to get own leaf from diff"))?;
            let encryption_keypair = own_diff_leaf.rekey(
                self.original_group.group_id(),
                self.original_group.ciphersuite(),
                self.original_group.version(), // XXX: openmls/openmls#1065
                credential_bundle,
                backend,
            )?;
            vec![encryption_keypair]
        };

        // Derive and apply an update path based on the previously
        // generated new leaf.
        let (plain_path, mut new_parent_keypairs, commit_secret) =
            self.diff.apply_own_update_path(
                backend,
                self.original_group.ciphersuite(),
                self.original_group.group_id().clone(),
                credential_bundle,
                leaf_index,
            )?;

        new_keypairs.append(&mut new_parent_keypairs);

        let serialized_group_context = self
            .original_group
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        // Encrypt the path to the correct recipient nodes.
        let encrypted_path = self.diff.encrypt_path(
            backend,
            self.original_group.ciphersuite(),
            &plain_path,
            &serialized_group_context,
            &exclusion_list,
            leaf_index,
        );
        let leaf_node = self
            .diff
            .leaf(leaf_index)
            .ok_or_else(|| LibraryError::custom("Couldn't find own leaf"))?
            .clone();
        let encrypted_path = UpdatePath::new(leaf_node.into(), encrypted_path);
        Ok(PathProcessingResult {
            commit_secret: Some(commit_secret),
            encrypted_path: Some(encrypted_path),
            plain_path: Some(plain_path),
            new_keypairs,
        })
    }
}
