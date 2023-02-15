use core::fmt::Debug;
use std::{collections::HashSet, mem};

use openmls_traits::key_store::OpenMlsKeyStore;

use super::{
    super::errors::*,
    proposals::{
        ProposalQueue, ProposalStore, QueuedAddProposal, QueuedPskProposal, QueuedRemoveProposal,
        QueuedUpdateProposal,
    },
    *,
};
use crate::{
    ciphersuite::signable::Verifiable,
    framing::mls_content::FramedContentBody,
    group::public_group::diff::StagedPublicGroupDiff,
    treesync::node::{
        encryption_keys::EncryptionKeyPair,
        leaf_node::{LeafNodeTbs, OpenMlsLeafNode, TreeInfoTbs, VerifiableLeafNode},
    },
};

impl CoreGroup {
    /// Stages a commit message that was sent by another group member.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Calculates the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag/membership tag
    /// Returns a [StagedCommit] that can be inspected and later merged
    /// into the group state with [CoreGroup::merge_commit()]
    /// This function does the following checks:
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
    ///  - ValSem105
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    ///  - ValSem200
    ///  - ValSem201
    ///  - ValSem202: Path must be the right length
    ///  - ValSem203: Path secrets must decrypt correctly
    ///  - ValSem204: Public keys from Path must be verified and match the
    ///               private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem243
    ///  - ValSem244
    /// Returns an error if the given commit was sent by the owner of this
    /// group.
    pub(crate) fn stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        own_leaf_nodes: &[OpenMlsLeafNode],
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<StagedCommit, StageCommitError> {
        // Extract the sender of the Commit message
        let ciphersuite = self.ciphersuite();

        // Verify epoch
        if mls_content.epoch() != self.context().epoch() {
            log::error!(
                "Epoch mismatch. Got {:?}, expected {:?}",
                mls_content.epoch(),
                self.context().epoch()
            );
            return Err(StageCommitError::EpochMismatch);
        }

        // Check that the sender is another member of the group
        let sender = mls_content.sender();

        if let Sender::Member(member) = sender {
            if *member == self.own_leaf_index() {
                return Err(StageCommitError::OwnCommit);
            }
        }

        // Extract Commit & Confirmation Tag from PublicMessage
        let commit = match mls_content.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => return Err(StageCommitError::WrongPlaintextContentType),
        };

        // ValSem244: External Commit, There MUST NOT be any referenced proposals.
        if *sender == Sender::NewMemberCommit
            && commit
                .proposals
                .iter()
                .any(|proposal| matches!(proposal, ProposalOrRef::Reference(_)))
        {
            return Err(StageCommitError::ExternalCommitValidation(
                ExternalCommitValidationError::ReferencedProposal,
            ));
        }

        // Build a queue with all proposals from the Commit and check that we have all
        // of the proposals by reference locally
        let proposal_queue = ProposalQueue::from_committed_proposals(
            ciphersuite,
            backend,
            commit.proposals.as_slice().to_vec(),
            proposal_store,
            sender,
        )
        .map_err(|e| match e {
            FromCommittedProposalsError::LibraryError(e) => StageCommitError::LibraryError(e),
            FromCommittedProposalsError::ProposalNotFound => StageCommitError::MissingProposal,
            FromCommittedProposalsError::SelfRemoval => StageCommitError::AttemptedSelfRemoval,
        })?;

        let commit_update_leaf_node = commit
            .path()
            .as_ref()
            .map(|update_path| update_path.leaf_node().clone());

        // Validate the staged proposals by doing the following checks:
        // ValSem101
        // ValSem102
        // ValSem104
        // ValSem105
        // ValSem106
        self.public_group.validate_add_proposals(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.public_group
            .validate_remove_proposals(&proposal_queue)?;

        let public_key_set = match sender {
            Sender::Member(leaf_index) => {
                // ValSem110
                // ValSem111
                // ValSem112
                self.public_group
                    .validate_update_proposals(&proposal_queue, *leaf_index)?
            }
            Sender::External(_) => {
                // A commit cannot be issued by a pre-configured sender.
                return Err(StageCommitError::SenderTypeExternal);
            }
            Sender::NewMemberProposal => {
                // A commit cannot be issued by a `NewMemberProposal` sender.
                return Err(StageCommitError::SenderTypeNewMemberProposal);
            }
            Sender::NewMemberCommit => {
                // ValSem240: External Commit, inline Proposals: There MUST be at least one ExternalInit proposal.
                // ValSem241: External Commit, inline Proposals: There MUST be at most one ExternalInit proposal.
                // ValSem242: External Commit must only cover inline proposal in allowlist (ExternalInit, Remove, PreSharedKey)
                // ValSem243: External Commit, inline Remove Proposal: The identity and the endpoint_id of the removed
                //            leaf are identical to the ones in the path KeyPackage.
                self.public_group
                    .validate_external_commit(&proposal_queue, commit_update_leaf_node.as_ref())?;
                // Since there are no update proposals in an External Commit we have no public keys to return
                HashSet::new()
            }
        };

        // Now we can actually look at the public keys as they might have changed.
        let sender_index = match sender {
            Sender::Member(leaf_index) => {
                // Own commits have to be merged directly instead of staging them.
                if leaf_index == &self.own_leaf_index() {
                    return Err(StageCommitError::InconsistentSenderIndex);
                }
                *leaf_index
            }
            Sender::NewMemberCommit => {
                let inline_proposals = commit.proposals.iter().filter_map(|p| {
                    if let ProposalOrRef::Proposal(inline_proposal) = p {
                        Some(Some(inline_proposal))
                    } else {
                        None
                    }
                });
                self.public_group
                    .free_leaf_index_after_remove(inline_proposals)?
            }
            _ => {
                return Err(StageCommitError::SenderTypeExternal);
            }
        };

        // Create provisional tree and apply proposals
        let mut diff = self.public_group.empty_diff();

        let apply_proposals_values =
            diff.apply_proposals(&proposal_queue, self.own_leaf_index())?;

        // Check if we were removed from the group
        if apply_proposals_values.self_removed {
            let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;
            return Ok(StagedCommit::new(
                proposal_queue,
                StagedCommitState::SelfRemoved(Box::new(staged_diff)),
            ));
        }

        // Determine if Commit has a path
        let (commit_secret, new_keypairs, new_leaf_keypair_option) =
            if let Some(path) = commit.path.clone() {
                // Verify the leaf node and PublicMessage membership tag
                // Note that the signature must have been verified already.
                // TODO #106: Support external members
                let leaf_node = path.leaf_node();
                // TODO: The clone here is unnecessary. But the leaf node structs are
                //       already too complex. This should be cleaned up in a follow
                //       up.
                let tbs = LeafNodeTbs::from(
                    leaf_node.clone(),
                    TreeInfoTbs::commit(self.group_id().clone(), sender_index),
                );
                let verifiable_leaf_node = VerifiableLeafNode {
                    tbs: &tbs,
                    signature: leaf_node.signature(),
                };
                let signature_public_key = leaf_node
                    .signature_key()
                    .clone()
                    .into_signature_public_key_enriched(self.ciphersuite().signature_algorithm());
                if verifiable_leaf_node
                    .verify_no_out(backend.crypto(), &signature_public_key)
                    .is_err()
                {
                    debug_assert!(
                        false,
                        "Verification failed of leaf node in commit path.\n\
                     Leaf node identity: {:?} ({})",
                        leaf_node.credential().identity(),
                        String::from_utf8(leaf_node.credential().identity().to_vec())
                            .unwrap_or_default()
                    );
                    return Err(StageCommitError::PathLeafNodeVerificationFailure);
                };

                // Make sure that the new path key package is valid
                self.public_group
                    .validate_path_key_package(path.leaf_node(), public_key_set)?;

                // Update the public group
                diff.apply_received_update_path(backend, ciphersuite, sender_index, &path)?;

                // Update group context
                diff.update_group_context(backend)?;

                // All keys from the previous epoch are potential decryption keypairs.
                let old_epoch_keypairs = self.read_epoch_keypairs(backend);

                // If we are processing an update proposal that originally came from
                // us, the keypair corresponding to the leaf in the update is also a
                // potential decryption keypair.
                let own_keypairs = own_leaf_nodes
                    .iter()
                    .map(|leaf_node| {
                        EncryptionKeyPair::read_from_key_store(backend, leaf_node.encryption_key())
                            .ok_or(StageCommitError::MissingDecryptionKey)
                    })
                    .collect::<Result<Vec<EncryptionKeyPair>, StageCommitError>>()?;

                let decryption_keypairs: Vec<&EncryptionKeyPair> = old_epoch_keypairs
                    .iter()
                    .chain(own_keypairs.iter())
                    .collect();

                // ValSem202: Path must be the right length
                // ValSem203: Path secrets must decrypt correctly
                // ValSem204: Public keys from Path must be verified and match the private keys from the direct path
                let (new_epoch_keypairs, commit_secret) = diff.decrypt_path(
                    backend,
                    &decryption_keypairs,
                    self.own_leaf_index(),
                    sender_index,
                    path.nodes(),
                    &apply_proposals_values.exclusion_list(),
                )?;

                // Check if one of our update proposals was applied. If so, we
                // need to store that keypair separately, because after merging
                // it needs to be removed from the key store separately and in
                // addition to the removal of the keypairs of the previous
                // epoch.
                let new_leaf_keypair_option = if let Some(leaf) = diff.leaf(self.own_leaf_index()) {
                    own_keypairs.into_iter().find_map(|keypair| {
                        if leaf.encryption_key() == keypair.public_key() {
                            Some(keypair)
                        } else {
                            None
                        }
                    })
                } else {
                    // We should have an own leaf at this point.
                    debug_assert!(false);
                    None
                };

                (commit_secret, new_epoch_keypairs, new_leaf_keypair_option)
            } else {
                if apply_proposals_values.path_required {
                    // ValSem201
                    return Err(StageCommitError::RequiredPathNotFound);
                }

                // Update group context
                diff.update_group_context(backend)?;

                (
                    CommitSecret::zero_secret(ciphersuite, self.version()),
                    vec![],
                    None,
                )
            };

        // Update the confirmed transcript hash before we compute the confirmation tag.
        diff.update_confirmed_transcript_hash(backend, mls_content)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        // Check if we need to include the init secret from an external commit
        // we applied earlier or if we use the one from the previous epoch.
        let joiner_secret = if let Some(ref external_init_proposal) =
            apply_proposals_values.external_init_proposal_option
        {
            // Decrypt the content and derive the external init secret.
            let external_priv = self
                .group_epoch_secrets()
                .external_secret()
                .derive_external_keypair(backend.crypto(), self.ciphersuite())
                .private
                .into();
            let init_secret = InitSecret::from_kem_output(
                backend,
                self.ciphersuite(),
                self.version(),
                &external_priv,
                external_init_proposal.kem_output(),
            )?;
            JoinerSecret::new(
                backend,
                commit_secret,
                &init_secret,
                &serialized_provisional_group_context,
            )
            .map_err(LibraryError::unexpected_crypto_error)?
        } else {
            JoinerSecret::new(
                backend,
                commit_secret,
                self.group_epoch_secrets.init_secret(),
                &serialized_provisional_group_context,
            )
            .map_err(LibraryError::unexpected_crypto_error)?
        };

        // Prepare the PskSecret
        let psk_secret =
            PskSecret::new(ciphersuite, backend, &apply_proposals_values.presharedkeys)?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)?;

        key_schedule
            .add_context(backend, &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        let received_confirmation_tag = mls_content
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        // Verify confirmation tag
        // ValSem205
        let own_confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, diff.group_context().confirmed_transcript_hash())
            .map_err(LibraryError::unexpected_crypto_error)?;
        if &own_confirmation_tag != received_confirmation_tag {
            log::error!("Confirmation tag mismatch");
            log_crypto!(trace, "  Got:      {:x?}", received_confirmation_tag);
            log_crypto!(trace, "  Expected: {:x?}", own_confirmation_tag);
            // TODO: We have tests expecting this error.
            //       They need to be rewritten.
            // debug_assert!(false, "Confirmation tag mismatch");
            return Err(StageCommitError::ConfirmationTagMismatch);
        }

        diff.update_interim_transcript_hash(ciphersuite, backend, own_confirmation_tag)?;

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.tree_size(),
                // The index should be the same on TreeSync and Diff.
                self.own_leaf_index(),
            );

        // Make the diff a staged diff. This finalizes the diff and no more changes can be applied to it.
        let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;

        let staged_commit_state =
            StagedCommitState::GroupMember(Box::new(MemberStagedCommitState {
                group_epoch_secrets: provisional_group_epoch_secrets,
                message_secrets: provisional_message_secrets,
                staged_diff,
                new_keypairs,
                new_leaf_keypair_option,
            }));

        Ok(StagedCommit::new(proposal_queue, staged_commit_state))
    }

    /// Merges a [StagedCommit] into the group state and optionally return a [`SecretTree`]
    /// from the previous epoch. The secret tree is returned if the Commit does not contain a self removal.
    ///
    /// This function should not fail and only returns a [`Result`], because it
    /// might throw a `LibraryError`.
    pub(crate) fn merge_commit<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        staged_commit: StagedCommit,
    ) -> Result<Option<MessageSecrets>, MergeCommitError<KeyStore::Error>> {
        // Get all keypairs from the old epoch, so we can later store the ones
        // that are still relevant in the new epoch.
        let old_epoch_keypairs = self.read_epoch_keypairs(backend);
        match staged_commit.state {
            StagedCommitState::SelfRemoved(staged_diff) => {
                self.public_group.merge_diff(*staged_diff);
                Ok(None)
            }
            StagedCommitState::GroupMember(state) => {
                self.group_epoch_secrets = state.group_epoch_secrets;

                // Replace the previous message secrets with the new ones and return the previous message secrets
                let mut message_secrets = state.message_secrets;
                mem::swap(
                    &mut message_secrets,
                    self.message_secrets_store.message_secrets_mut(),
                );

                self.public_group.merge_diff(state.staged_diff);

                // TODO #1194: Group storage and key storage should be
                // correlated s.t. there is no divergence between key material
                // and group state.

                let leaf_keypair = if let Some(keypair) = &state.new_leaf_keypair_option {
                    vec![keypair.clone()]
                } else {
                    vec![]
                };

                // Figure out which keys we need in the new epoch.
                let new_owned_encryption_keys = self
                    .public_group
                    .treesync()
                    .owned_encryption_keys(self.own_leaf_index());
                // From the old and new keys, keep the ones that are still relevant in the new epoch.
                let epoch_keypairs: Vec<EncryptionKeyPair> = old_epoch_keypairs
                    .into_iter()
                    .chain(state.new_keypairs.into_iter())
                    .chain(leaf_keypair.into_iter())
                    .filter(|keypair| new_owned_encryption_keys.contains(keypair.public_key()))
                    .collect();
                // We should have private keys for all owned encryption keys.

                debug_assert_eq!(new_owned_encryption_keys.len(), epoch_keypairs.len());
                if new_owned_encryption_keys.len() != epoch_keypairs.len() {
                    return Err(LibraryError::custom(
                        "We should have all the private key material we need.",
                    )
                    .into());
                }
                // Store the relevant keys under the new epoch
                self.store_epoch_keypairs(backend, epoch_keypairs.as_slice())
                    .map_err(MergeCommitError::KeyStoreError)?;
                // Delete the old keys.
                self.delete_previous_epoch_keypairs(backend)
                    .map_err(MergeCommitError::KeyStoreError)?;
                if let Some(keypair) = state.new_leaf_keypair_option {
                    keypair
                        .delete_from_key_store(backend)
                        .map_err(MergeCommitError::KeyStoreError)?;
                }

                Ok(Some(message_secrets))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum StagedCommitState {
    SelfRemoved(Box<StagedPublicGroupDiff>),
    GroupMember(Box<MemberStagedCommitState>),
}

/// Contains the changes from a commit to the group state.
#[derive(Debug, Serialize, Deserialize)]
pub struct StagedCommit {
    staged_proposal_queue: ProposalQueue,
    state: StagedCommitState,
}

impl StagedCommit {
    /// Create a new [`StagedCommit`] from the provisional group state created
    /// during the commit process.
    pub(crate) fn new(staged_proposal_queue: ProposalQueue, state: StagedCommitState) -> Self {
        StagedCommit {
            staged_proposal_queue,
            state,
        }
    }

    /// Returns the Add proposals that are covered by the Commit message as in iterator over [QueuedAddProposal].
    pub fn add_proposals(&self) -> impl Iterator<Item = QueuedAddProposal> {
        self.staged_proposal_queue.add_proposals()
    }

    /// Returns the Remove proposals that are covered by the Commit message as in iterator over [QueuedRemoveProposal].
    pub fn remove_proposals(&self) -> impl Iterator<Item = QueuedRemoveProposal> {
        self.staged_proposal_queue.remove_proposals()
    }

    /// Returns the Update proposals that are covered by the Commit message as in iterator over [QueuedUpdateProposal].
    pub fn update_proposals(&self) -> impl Iterator<Item = QueuedUpdateProposal> {
        self.staged_proposal_queue.update_proposals()
    }

    /// Returns the PresharedKey proposals that are covered by the Commit message as in iterator over [QueuedPskProposal].
    pub fn psk_proposals(&self) -> impl Iterator<Item = QueuedPskProposal> {
        self.staged_proposal_queue.psk_proposals()
    }

    /// Returns `true` if the member was removed through a proposal covered by this Commit message
    /// and `false` otherwise.
    pub fn self_removed(&self) -> bool {
        matches!(self.state, StagedCommitState::SelfRemoved(_))
    }
}

/// This struct is used internally by [StagedCommit] to encapsulate all the modified group state.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MemberStagedCommitState {
    group_epoch_secrets: GroupEpochSecrets,
    message_secrets: MessageSecrets,
    staged_diff: StagedPublicGroupDiff,
    new_keypairs: Vec<EncryptionKeyPair>,
    new_leaf_keypair_option: Option<EncryptionKeyPair>,
}

impl MemberStagedCommitState {
    pub(crate) fn new(
        group_epoch_secrets: GroupEpochSecrets,
        message_secrets: MessageSecrets,
        staged_diff: StagedPublicGroupDiff,
        new_keypairs: Vec<EncryptionKeyPair>,
        new_leaf_keypair_option: Option<EncryptionKeyPair>,
    ) -> Self {
        Self {
            group_epoch_secrets,
            message_secrets,
            staged_diff,
            new_keypairs,
            new_leaf_keypair_option,
        }
    }
}
