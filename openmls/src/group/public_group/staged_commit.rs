use super::{super::errors::*, diff::apply_proposals::ApplyProposalsValues, *};
use crate::{
    ciphersuite::signable::Verifiable,
    framing::mls_auth_content::AuthenticatedContent,
    framing::mls_content::FramedContentBody,
    group::core_group::proposals::{ProposalQueue, ProposalStore},
    group::{
        public_group::diff::StagedPublicGroupDiff,
        staged_commit::{MemberStagedCommitState, StagedCommitState},
        StagedCommit,
    },
    messages::{proposals::ProposalOrRef, Commit},
    prelude_test::Sender,
    schedule::{
        psk::PskSecret, EpochSecrets, GroupEpochSecrets, InitSecret, JoinerSecret, KeySchedule,
    },
    treesync::node::{
        encryption_keys::EncryptionKeyPair,
        leaf_node::{LeafNodeTbs, TreeInfoTbs, VerifiableLeafNode},
    },
};
use std::collections::HashSet;

pub(crate) struct PrivateGroupParams<'a> {
    pub(crate) own_leaf_index: LeafNodeIndex,
    pub(crate) epoch_secrets: &'a GroupEpochSecrets,
    pub(crate) old_epoch_keypairs: Vec<EncryptionKeyPair>,
    pub(crate) leaf_node_keypairs: Vec<EncryptionKeyPair>,
}

impl PublicGroup {
    fn validate_commit<'a>(
        &self,
        mls_content: &'a AuthenticatedContent,
        proposal_store: &ProposalStore,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(&'a Commit, ProposalQueue, LeafNodeIndex), StageCommitError> {
        let ciphersuite = self.ciphersuite();

        // Verify epoch
        if mls_content.epoch() != self.group_context().epoch() {
            log::error!(
                "Epoch mismatch. Got {:?}, expected {:?}",
                mls_content.epoch(),
                self.group_context().epoch()
            );
            return Err(StageCommitError::EpochMismatch);
        }

        // Extract Commit & Confirmation Tag from PublicMessage
        let commit = match mls_content.content() {
            FramedContentBody::Commit(commit) => commit,
            _ => return Err(StageCommitError::WrongPlaintextContentType),
        };

        let sender = mls_content.sender();
        // ValSem244: External Commit, There MUST NOT be any referenced proposals.
        if sender == &Sender::NewMemberCommit
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
        self.validate_add_proposals(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.validate_remove_proposals(&proposal_queue)?;

        let public_key_set = match sender {
            Sender::Member(leaf_index) => {
                // ValSem110
                // ValSem111
                // ValSem112
                self.validate_update_proposals(&proposal_queue, *leaf_index)?
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
                self.validate_external_commit(&proposal_queue, commit_update_leaf_node.as_ref())?;
                // Since there are no update proposals in an External Commit we have no public keys to return
                HashSet::new()
            }
        };

        // Now we can actually look at the public keys as they might have changed.
        let sender_index = match sender {
            Sender::Member(leaf_index) => *leaf_index,
            Sender::NewMemberCommit => {
                let inline_proposals = commit.proposals.iter().filter_map(|p| {
                    if let ProposalOrRef::Proposal(inline_proposal) = p {
                        Some(Some(inline_proposal))
                    } else {
                        None
                    }
                });
                self.free_leaf_index(inline_proposals)?
            }
            _ => {
                return Err(StageCommitError::SenderTypeExternal);
            }
        };

        // Validation in case of path
        if let Some(path) = commit.path.clone() {
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
            self.validate_path_key_package(path.leaf_node(), public_key_set)?;
        }

        Ok((commit, proposal_queue, sender_index))
    }

    #[allow(unused)]
    pub(crate) fn stage_commit_public(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(ProposalQueue, StagedPublicGroupDiff), StageCommitError> {
        let ciphersuite = self.ciphersuite();

        let (commit, proposal_queue, sender_index) =
            self.validate_commit(mls_content, proposal_store, backend)?;

        // Create provisional tree and apply proposals
        let mut diff = self.empty_diff();

        let apply_proposals_values = diff.apply_proposals(&proposal_queue, None)?;

        // Determine if Commit has a path
        if let Some(path) = commit.path.clone() {
            // Update the public group
            diff.apply_received_update_path(backend, ciphersuite, sender_index, &path)?;

            // Update group context
            diff.update_group_context(backend)?;
        } else if apply_proposals_values.path_required {
            // ValSem201
            return Err(StageCommitError::RequiredPathNotFound);
        }

        // Update the confirmed transcript hash
        diff.update_confirmed_transcript_hash(backend, mls_content)?;

        let confirmation_tag = mls_content
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        diff.update_interim_transcript_hash(ciphersuite, backend, confirmation_tag.clone())?;

        // Make the diff a staged diff. This finalizes the diff and no more changes can be applied to it.
        let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;

        Ok((proposal_queue, staged_diff))
    }

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
    pub(crate) fn stage_commit_private(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        backend: &impl OpenMlsCryptoProvider,
        private_group_params: PrivateGroupParams,
    ) -> Result<StagedCommit, StageCommitError> {
        let PrivateGroupParams {
            own_leaf_index,
            epoch_secrets,
            old_epoch_keypairs,
            leaf_node_keypairs,
        } = private_group_params;

        let ciphersuite = self.ciphersuite();

        let (commit, proposal_queue, sender_index) =
            self.validate_commit(mls_content, proposal_store, backend)?;

        // Create provisional tree and apply proposals
        let mut diff = self.empty_diff();

        let apply_proposals_values = diff.apply_proposals(&proposal_queue, own_leaf_index)?;

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
                // Update the public group
                diff.apply_received_update_path(backend, ciphersuite, sender_index, &path)?;

                // Update group context
                diff.update_group_context(backend)?;

                let decryption_keypairs: Vec<&EncryptionKeyPair> = old_epoch_keypairs
                    .iter()
                    .chain(leaf_node_keypairs.iter())
                    .collect();

                // ValSem202: Path must be the right length
                // ValSem203: Path secrets must decrypt correctly
                // ValSem204: Public keys from Path must be verified and match the private keys from the direct path
                let (new_epoch_keypairs, commit_secret) = diff.decrypt_path(
                    backend,
                    &decryption_keypairs,
                    own_leaf_index,
                    sender_index,
                    path.nodes(),
                    &apply_proposals_values.exclusion_list(),
                )?;

                // Check if one of our update proposals was applied. If so, we
                // need to store that keypair separately, because after merging
                // it needs to be removed from the key store separately and in
                // addition to the removal of the keypairs of the previous
                // epoch.
                let new_leaf_keypair_option = if let Some(leaf) = diff.leaf(own_leaf_index) {
                    leaf_node_keypairs.into_iter().find_map(|keypair| {
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

        let (provisional_group_secrets, provisional_message_secrets) = self
            .derive_epoch_secrets(
                backend,
                apply_proposals_values,
                epoch_secrets,
                commit_secret,
                &serialized_provisional_group_context,
            )?
            .split_secrets(
                serialized_provisional_group_context,
                diff.tree_size(),
                own_leaf_index,
            );

        let received_confirmation_tag = mls_content
            .confirmation_tag()
            .ok_or(StageCommitError::ConfirmationTagMissing)?;

        // Verify confirmation tag
        // ValSem205
        let own_confirmation_tag = provisional_message_secrets
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

        // Make the diff a staged diff. This finalizes the diff and no more changes can be applied to it.
        let staged_diff = diff.into_staged_diff(backend, ciphersuite)?;

        let staged_commit_state =
            StagedCommitState::GroupMember(Box::new(MemberStagedCommitState::new(
                provisional_group_secrets,
                provisional_message_secrets,
                staged_diff,
                new_keypairs,
                new_leaf_keypair_option,
            )));

        Ok(StagedCommit::new(proposal_queue, staged_commit_state))
    }

    fn derive_epoch_secrets(
        &self,
        backend: &impl OpenMlsCryptoProvider,
        apply_proposals_values: ApplyProposalsValues,
        epoch_secrets: &GroupEpochSecrets,
        commit_secret: CommitSecret,
        serialized_provisional_group_context: &[u8],
    ) -> Result<EpochSecrets, StageCommitError> {
        // Check if we need to include the init secret from an external commit
        // we applied earlier or if we use the one from the previous epoch.
        let joiner_secret = if let Some(ref external_init_proposal) =
            apply_proposals_values.external_init_proposal_option
        {
            // Decrypt the content and derive the external init secret.
            let external_priv = epoch_secrets
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
            JoinerSecret::new(backend, commit_secret, &init_secret)
                .map_err(LibraryError::unexpected_crypto_error)?
        } else {
            JoinerSecret::new(backend, commit_secret, epoch_secrets.init_secret())
                .map_err(LibraryError::unexpected_crypto_error)?
        };

        // Prepare the PskSecret
        let psk_secret = PskSecret::new(
            self.ciphersuite(),
            backend,
            &apply_proposals_values.presharedkeys,
        )?;

        // Create key schedule
        let mut key_schedule =
            KeySchedule::init(self.ciphersuite(), backend, joiner_secret, psk_secret)?;

        key_schedule
            .add_context(backend, serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        Ok(key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?)
    }
}
