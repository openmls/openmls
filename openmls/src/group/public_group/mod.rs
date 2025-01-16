//! # Public Groups
//!
//! There are a few use-cases that require the tracking of an MLS group based on
//! [`PublicMessage`]s, e.g. for group membership tracking by a delivery
//! service.
//!
//! This module and its submodules contain the [`PublicGroup`] struct, as well
//! as associated helper structs the goal of which is to enable this
//! functionality.
//!
//! To avoid duplication of code and functionality, [`MlsGroup`] internally
//! relies on a [`PublicGroup`] as well.

use std::collections::HashSet;

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};

use self::{
    diff::{PublicGroupDiff, StagedPublicGroupDiff},
    errors::CreationFromExternalError,
};
use super::{
    proposal_store::{ProposalStore, QueuedProposal},
    GroupContext, GroupId, Member, StagedCommit,
};
#[cfg(test)]
use crate::treesync::{node::parent_node::PlainUpdatePathNode, treekem::UpdatePathNode};
use crate::{
    binary_tree::{
        array_representation::{direct_path, TreeSize},
        LeafNodeIndex,
    },
    ciphersuite::{hash_ref::ProposalRef, signable::Verifiable},
    error::LibraryError,
    extensions::RequiredCapabilitiesExtension,
    framing::InterimTranscriptHashInput,
    messages::{
        group_info::{GroupInfo, VerifiableGroupInfo},
        proposals::{Proposal, ProposalOrRefType, ProposalType},
        ConfirmationTag, PathSecret,
    },
    schedule::CommitSecret,
    storage::PublicStorageProvider,
    treesync::{
        errors::{DerivePathError, TreeSyncFromNodesError},
        node::{
            encryption_keys::{EncryptionKey, EncryptionKeyPair},
            leaf_node::LeafNode,
        },
        RatchetTree, RatchetTreeIn, TreeSync,
    },
    versions::ProtocolVersion,
};
#[cfg(doc)]
use crate::{framing::PublicMessage, group::MlsGroup};

pub(crate) mod builder;
pub(crate) mod diff;
pub mod errors;
pub mod process;
pub(crate) mod staged_commit;
#[cfg(test)]
mod tests;
mod validation;

/// This struct holds all public values of an MLS group.
#[derive(Debug)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub struct PublicGroup {
    treesync: TreeSync,
    proposal_store: ProposalStore,
    group_context: GroupContext,
    interim_transcript_hash: Vec<u8>,
    // Most recent confirmation tag. Kept here for verification purposes.
    confirmation_tag: ConfirmationTag,
}

/// This is a wrapper type, because we can't implement the storage traits on `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterimTranscriptHash(pub Vec<u8>);

impl PublicGroup {
    /// Create a new PublicGroup from a [`TreeSync`] instance and a
    /// [`GroupInfo`].
    pub(crate) fn new(
        crypto: &impl OpenMlsCrypto,
        treesync: TreeSync,
        group_context: GroupContext,
        initial_confirmation_tag: ConfirmationTag,
    ) -> Result<Self, LibraryError> {
        let interim_transcript_hash = {
            let input = InterimTranscriptHashInput::from(&initial_confirmation_tag);

            input.calculate_interim_transcript_hash(
                crypto,
                group_context.ciphersuite(),
                group_context.confirmed_transcript_hash(),
            )?
        };

        Ok(PublicGroup {
            treesync,
            proposal_store: ProposalStore::new(),
            group_context,
            interim_transcript_hash,
            confirmation_tag: initial_confirmation_tag,
        })
    }

    /// Create a [`PublicGroup`] instance to start tracking an existing MLS group.
    ///
    /// This function performs basic validation checks and returns an error if
    /// one of the checks fails. See [`CreationFromExternalError`] for more
    /// details.
    pub fn from_external<StorageProvider, StorageError>(
        crypto: &impl OpenMlsCrypto,
        storage: &StorageProvider,
        ratchet_tree: RatchetTreeIn,
        verifiable_group_info: VerifiableGroupInfo,
        proposal_store: ProposalStore,
    ) -> Result<(Self, GroupInfo), CreationFromExternalError<StorageError>>
    where
        StorageProvider: PublicStorageProvider<Error = StorageError>,
    {
        let ciphersuite = verifiable_group_info.ciphersuite();

        let group_id = verifiable_group_info.group_id();
        let ratchet_tree = ratchet_tree
            .into_verified(ciphersuite, crypto, group_id)
            .map_err(|e| {
                CreationFromExternalError::TreeSyncError(TreeSyncFromNodesError::RatchetTreeError(
                    e,
                ))
            })?;

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the group info, since we need to find the Credential to verify the
        // signature against.
        let treesync = TreeSync::from_ratchet_tree(crypto, ciphersuite, ratchet_tree)?;

        let mut encryption_keys = HashSet::new();

        // Perform basic checks that the leaf nodes in the ratchet tree are valid
        // These checks only do those that don't need group context. We do the full
        // checks later, but do these here to fail early in case of funny business
        treesync.full_leaves().try_for_each(|leaf_node| {
            leaf_node.validate_locally()?;

            // Check that no two nodes share an encryption key.
            // This is a bit stronger than what the spec requires: It requires that the encryption keys
            // in parent nodes and unmerged leaves must be unique. Here, we check that all encryption
            // keys (all leaf nodes, incl. unmerged and all parent nodes) are unique.
            //
            // https://validation.openmls.tech/#valn1410
            if !encryption_keys.insert(leaf_node.encryption_key()) {
                return Err(CreationFromExternalError::DuplicateEncryptionKey);
            }

            Ok(())
        })?;

        // For each non-empty parent node and each entry in the node's unmerged_leaves field:
        treesync
            .full_parents()
            .try_for_each(|(parent_index, parent_node)| {
                // Check that no two nodes share an encryption key.
                // This is a bit stronger than what the spec requires: It requires that the encryption keys
                // in parent nodes and unmerged leaves must be unique. Here, we check that all encryption
                // keys (all leaf nodes, incl. unmerged and all parent nodes) are unique.
                //
                // https://validation.openmls.tech/#valn1410
                if !encryption_keys.insert(parent_node.encryption_key()) {
                    return Err(CreationFromExternalError::DuplicateEncryptionKey);
                }

                parent_node
                    .unmerged_leaves()
                    .iter()
                    .try_for_each(|leaf_index| {
                        let path = direct_path(*leaf_index, treesync.tree_size());

                        // https://validation.openmls.tech/#valn1408
                        // Verify that the entry represents a non-blank leaf node that is a descendant of the
                        // parent node.
                        let this_parent_offset = path
                            .iter()
                            .position(|x| x == &parent_index)
                            .ok_or(
                            CreationFromExternalError::<StorageError>::UnmergedLeafNotADescendant,
                        )?;
                        let path_leaf_to_this = &path[..this_parent_offset];


                        // https://validation.openmls.tech/#valn1409
                        // Verify that every non-blank intermediate node between the leaf node and the parent
                        // node also has an entry for the leaf node in its unmerged_leaves.
                        path_leaf_to_this
                            .iter()
                            .try_for_each(|intermediate_index| {
                                // None would be blank, and we don't care about those
                                if let Some(intermediate_node) = treesync
                                    .parent(*intermediate_index) {
                                    if !intermediate_node.unmerged_leaves().contains(leaf_index) {
                                        return Err(CreationFromExternalError::<StorageError>::IntermediateNodeMissingUnmergedLeaf);
                                    }
                                }

                                Ok(())
                            })
                    })
            })?;

        // https://validation.openmls.tech/#valn1402
        let group_info: GroupInfo = {
            let signer_signature_key = treesync
                .leaf(verifiable_group_info.signer())
                .ok_or(CreationFromExternalError::UnknownSender)?
                .signature_key()
                .clone()
                .into_signature_public_key_enriched(ciphersuite.signature_algorithm());

            verifiable_group_info
                .verify(crypto, &signer_signature_key)
                .map_err(|_| CreationFromExternalError::InvalidGroupInfoSignature)?
        };

        // https://validation.openmls.tech/#valn1405
        if treesync.tree_hash() != group_info.group_context().tree_hash() {
            return Err(CreationFromExternalError::TreeHashMismatch);
        }

        if group_info.group_context().protocol_version() != ProtocolVersion::Mls10 {
            return Err(CreationFromExternalError::UnsupportedMlsVersion);
        }

        let group_context = group_info.group_context().clone();

        let interim_transcript_hash = {
            let input = InterimTranscriptHashInput::from(group_info.confirmation_tag());

            input.calculate_interim_transcript_hash(
                crypto,
                group_context.ciphersuite(),
                group_context.confirmed_transcript_hash(),
            )?
        };

        let public_group = Self {
            treesync,
            group_context,
            interim_transcript_hash,
            confirmation_tag: group_info.confirmation_tag().clone(),
            proposal_store,
        };

        // Fully check that the leaf nodes in the ratchet tree are valid
        // https://validation.openmls.tech/#valn1407
        public_group
            .treesync
            .full_leaves()
            .try_for_each(|leaf_node| public_group.validate_leaf_node(leaf_node))?;

        public_group
            .store(storage)
            .map_err(CreationFromExternalError::WriteToStorageError)?;

        Ok((public_group, group_info))
    }

    /// Returns the index of the sender of a staged, external commit.
    pub fn ext_commit_sender_index(
        &self,
        commit: &StagedCommit,
    ) -> Result<LeafNodeIndex, LibraryError> {
        self.leftmost_free_index(commit.queued_proposals().filter_map(|p| {
            if matches!(p.proposal_or_ref_type(), ProposalOrRefType::Proposal) {
                Some(Some(p.proposal()))
            } else {
                None
            }
        }))
    }

    /// Returns the leftmost free leaf index.
    ///
    /// For External Commits of the "resync" type, this returns the index
    /// of the sender.
    ///
    /// The proposals must be validated before calling this function.
    pub(crate) fn leftmost_free_index<'a>(
        &self,
        mut inline_proposals: impl Iterator<Item = Option<&'a Proposal>>,
    ) -> Result<LeafNodeIndex, LibraryError> {
        // Leftmost free leaf in the tree
        let free_leaf_index = self.treesync().free_leaf_index();
        // Returns the first remove proposal (if there is one)
        let remove_proposal_option = inline_proposals
            .find(|proposal| match proposal {
                Some(p) => p.is_type(ProposalType::Remove),
                None => false,
            })
            .flatten();
        let leaf_index = if let Some(remove_proposal) = remove_proposal_option {
            if let Proposal::Remove(remove_proposal) = remove_proposal {
                let removed_index = remove_proposal.removed();
                // The committer should always be in the left-most leaf.
                if removed_index < free_leaf_index {
                    removed_index
                } else {
                    free_leaf_index
                }
            } else {
                return Err(LibraryError::custom("missing key package"));
            }
        } else {
            free_leaf_index
        };
        Ok(leaf_index)
    }

    /// Create an empty  [`PublicGroupDiff`] based on this [`PublicGroup`].
    pub(crate) fn empty_diff(&self) -> PublicGroupDiff {
        PublicGroupDiff::new(self)
    }

    /// Merge the changes performed on the [`PublicGroupDiff`] into this
    /// [`PublicGroup`].
    ///
    /// **NOTE:** The caller must ensure that the group context in the `diff` is
    ///           updated before calling this function with `update_group_context`.
    pub(crate) fn merge_diff(&mut self, diff: StagedPublicGroupDiff) {
        self.treesync.merge_diff(diff.staged_diff);
        self.group_context = diff.group_context;
        self.interim_transcript_hash = diff.interim_transcript_hash;
        self.confirmation_tag = diff.confirmation_tag;
    }

    /// Derives [`EncryptionKeyPair`]s for the nodes in the shared direct path
    /// of the leaves with index `leaf_index` and `sender_index`.  This function
    /// also checks that the derived public keys match the existing public keys.
    ///
    /// Returns the [`CommitSecret`] derived from the path secret of the root
    /// node, as well as the derived [`EncryptionKeyPair`]s. Returns an error if
    /// the target leaf is outside of the tree.
    ///
    /// Returns [`DerivePathError::PublicKeyMismatch`] if the derived keys don't
    /// match with the existing ones.
    ///
    /// Returns [`DerivePathError::LibraryError`] if the sender_index is not
    /// in the tree.
    pub(crate) fn derive_path_secrets(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        path_secret: PathSecret,
        sender_index: LeafNodeIndex,
        leaf_index: LeafNodeIndex,
    ) -> Result<(Vec<EncryptionKeyPair>, CommitSecret), DerivePathError> {
        self.treesync.derive_path_secrets(
            crypto,
            ciphersuite,
            path_secret,
            sender_index,
            leaf_index,
        )
    }

    /// Get an iterator over all [`Member`]s of this [`PublicGroup`].
    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.treesync().full_leave_members()
    }

    /// Export the nodes of the public tree.
    pub fn export_ratchet_tree(&self) -> RatchetTree {
        self.treesync().export_ratchet_tree()
    }

    /// Add the [`QueuedProposal`] to the [`PublicGroup`]s internal [`ProposalStore`].
    pub fn add_proposal<Storage: PublicStorageProvider>(
        &mut self,
        storage: &Storage,
        proposal: QueuedProposal,
    ) -> Result<(), Storage::Error> {
        storage.queue_proposal(self.group_id(), &proposal.proposal_reference(), &proposal)?;
        self.proposal_store.add(proposal);
        Ok(())
    }

    /// Remove the Proposal with the given [`ProposalRef`] from the [`PublicGroup`]s internal [`ProposalStore`].
    pub fn remove_proposal<Storage: PublicStorageProvider>(
        &mut self,
        storage: &Storage,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Storage::Error> {
        storage.remove_proposal(self.group_id(), proposal_ref)?;
        self.proposal_store.remove(proposal_ref);
        Ok(())
    }

    /// Return all queued proposals
    pub fn queued_proposals<Storage: PublicStorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Storage::Error> {
        storage.queued_proposals(self.group_id())
    }
}

// Getters
impl PublicGroup {
    /// Get the ciphersuite.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.group_context.ciphersuite()
    }

    /// Get the version.
    pub fn version(&self) -> ProtocolVersion {
        self.group_context.protocol_version()
    }

    /// Get the group id.
    pub fn group_id(&self) -> &GroupId {
        self.group_context.group_id()
    }

    /// Get the group context.
    pub fn group_context(&self) -> &GroupContext {
        &self.group_context
    }

    /// Get the required capabilities.
    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.group_context.required_capabilities()
    }

    /// Get treesync.
    fn treesync(&self) -> &TreeSync {
        &self.treesync
    }

    /// Get confirmation tag.
    pub fn confirmation_tag(&self) -> &ConfirmationTag {
        &self.confirmation_tag
    }

    /// Return a reference to the leaf at the given `LeafNodeIndex` or `None` if the
    /// leaf is blank.
    pub fn leaf(&self, leaf_index: LeafNodeIndex) -> Option<&LeafNode> {
        self.treesync().leaf(leaf_index)
    }

    /// Returns the tree size
    pub(crate) fn tree_size(&self) -> TreeSize {
        self.treesync().tree_size()
    }

    fn interim_transcript_hash(&self) -> &[u8] {
        &self.interim_transcript_hash
    }

    /// Return a vector containing all [`EncryptionKey`]s for which the owner of
    /// the given `leaf_index` should have private key material.
    pub(crate) fn owned_encryption_keys(&self, leaf_index: LeafNodeIndex) -> Vec<EncryptionKey> {
        self.treesync().owned_encryption_keys(leaf_index)
    }

    /// Stores the [`PublicGroup`] to storage. Called from methods creating a new group and mutating an
    /// existing group, both inside [`PublicGroup`] and in [`MlsGroup`].
    ///
    /// [`MlsGroup`]: crate::group::MlsGroup
    pub(crate) fn store<Storage: PublicStorageProvider>(
        &self,
        storage: &Storage,
    ) -> Result<(), Storage::Error> {
        let group_id = self.group_context.group_id();
        storage.write_tree(group_id, self.treesync())?;
        storage.write_confirmation_tag(group_id, self.confirmation_tag())?;
        storage.write_context(group_id, self.group_context())?;
        storage.write_interim_transcript_hash(
            group_id,
            &InterimTranscriptHash(self.interim_transcript_hash.clone()),
        )?;
        Ok(())
    }

    /// Deletes the [`PublicGroup`] from storage.
    pub fn delete<Storage: PublicStorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<(), Storage::Error> {
        storage.delete_tree(group_id)?;
        storage.delete_confirmation_tag(group_id)?;
        storage.delete_context(group_id)?;
        storage.delete_interim_transcript_hash(group_id)?;

        Ok(())
    }

    /// Loads the [`PublicGroup`] corresponding to a [`GroupId`] from storage.
    pub fn load<Storage: PublicStorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Option<Self>, Storage::Error> {
        let treesync = storage.tree(group_id)?;
        let proposals: Vec<(ProposalRef, QueuedProposal)> = storage.queued_proposals(group_id)?;
        let group_context = storage.group_context(group_id)?;
        let interim_transcript_hash: Option<InterimTranscriptHash> =
            storage.interim_transcript_hash(group_id)?;
        let confirmation_tag = storage.confirmation_tag(group_id)?;
        let mut proposal_store = ProposalStore::new();

        for (_ref, proposal) in proposals {
            proposal_store.add(proposal);
        }

        let build = || -> Option<Self> {
            Some(Self {
                treesync: treesync?,
                proposal_store,
                group_context: group_context?,
                interim_transcript_hash: interim_transcript_hash?.0,
                confirmation_tag: confirmation_tag?,
            })
        };

        Ok(build())
    }

    /// Returns a reference to the [`ProposalStore`].
    pub(crate) fn proposal_store(&self) -> &ProposalStore {
        &self.proposal_store
    }

    /// Returns a mutable reference to the [`ProposalStore`].
    pub(crate) fn proposal_store_mut(&mut self) -> &mut ProposalStore {
        &mut self.proposal_store
    }
}

// Test functions
#[cfg(any(feature = "test-utils", test))]
impl PublicGroup {
    pub(crate) fn context_mut(&mut self) -> &mut GroupContext {
        &mut self.group_context
    }

    #[cfg(test)]
    pub(crate) fn set_group_context(&mut self, group_context: GroupContext) {
        self.group_context = group_context;
    }

    #[cfg(test)]
    pub(crate) fn encrypt_path(
        &self,
        provider: &impl crate::storage::OpenMlsProvider,
        ciphersuite: Ciphersuite,
        path: &[PlainUpdatePathNode],
        group_context: &[u8],
        exclusion_list: &HashSet<&LeafNodeIndex>,
        own_leaf_index: LeafNodeIndex,
    ) -> Result<Vec<UpdatePathNode>, LibraryError> {
        self.treesync().empty_diff().encrypt_path(
            provider.crypto(),
            ciphersuite,
            path,
            group_context,
            exclusion_list,
            own_leaf_index,
        )
    }
}
