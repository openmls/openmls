use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::signable::Signable,
    group::{config::CryptoConfig, core_group::*, errors::CreateCommitError},
    treesync::{
        diff::TreeSyncDiff,
        node::{leaf_node::OpenMlsLeafNode, parent_node::PlainUpdatePathNode},
        treekem::{PlaintextSecret, UpdatePath},
    },
    versions::ProtocolVersion,
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    proposals::ProposalQueue,
    staged_commit::{MemberStagedCommitState, StagedCommit, StagedCommitState},
};

/// A helper struct which contains the values resulting from the preparation of
/// a commit with path.
#[derive(Default)]
struct PathProcessingResult {
    commit_secret: Option<CommitSecret>,
    encrypted_path: Option<UpdatePath>,
    plain_path: Option<Vec<PlainUpdatePathNode>>,
}

impl CoreGroup {
    pub(crate) fn create_commit(
        &self,
        params: CreateCommitParams,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<CreateCommitResult, CreateCommitError> {
        let ciphersuite = self.ciphersuite();

        // If this is an external commit, we don't have an `own_leaf_index` set
        // yet. Instead, we use the index in which we will be put in course of
        // this commit. Our index is determined as if we'd be added through an
        // Add proposal. However, since this might be the "resync" flavour of an
        // external commit, it could be that we're first removing our past self
        // from the group, in which case, we can't just take the next free leaf
        // in the existing tree. Note, that we have to determine the index here
        // (before we actually add our own leaf), because it's needed in the
        // process of proposal filtering and application.
        let (sender, own_leaf_index) = match params.commit_type() {
            CommitType::External => {
                // If this is a "resync" external commit, it should contain a
                // `remove` proposal with the index of our previous self in the
                // group.
                let leaf_index =
                    self.free_leaf_index(params.inline_proposals().iter().map(Some))?;
                (Sender::NewMemberCommit, leaf_index)
            }
            CommitType::Member => (
                Sender::build_member(self.own_leaf_index()),
                self.own_leaf_index(),
            ),
        };

        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            backend,
            sender.clone(),
            params.proposal_store(),
            params.inline_proposals(),
            own_leaf_index,
        )
        .map_err(|e| match e {
            crate::group::errors::ProposalQueueError::LibraryError(e) => e.into(),
            crate::group::errors::ProposalQueueError::ProposalNotFound => {
                CreateCommitError::MissingProposal
            }
            crate::group::errors::ProposalQueueError::SenderError(_) => {
                CreateCommitError::WrongProposalSenderType
            }
        })?;

        // TODO: #581 Filter proposals by support
        // 11.2:
        // Proposals with a non-default proposal type MUST NOT be included in a commit
        // unless the proposal type is supported by all the members of the group that
        // will process the Commit (i.e., not including any members being added
        // or removed by the Commit).

        let proposal_reference_list = proposal_queue.commit_list();

        // Make a copy of the current tree to apply proposals safely
        let mut diff: TreeSyncDiff = self.treesync().empty_diff();

        // If this is an external commit we have to set our own leaf index manually
        if params.commit_type() == CommitType::External {
            diff.set_own_index(own_leaf_index);
        }

        // Validate the proposals by doing the following checks:

        // ValSem100
        // ValSem101
        // ValSem102
        // ValSem103
        // ValSem104
        // ValSem105
        // ValSem106
        self.validate_add_proposals(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.validate_remove_proposals(&proposal_queue)?;
        // Validate update proposals for member commits
        if let Sender::Member(sender_index) = &sender {
            // ValSem109
            // ValSem110
            // ValSem111
            // ValSem112
            self.validate_update_proposals(&proposal_queue, *sender_index)?;
        }

        // Apply proposals to tree
        let apply_proposals_values = self
            .apply_proposals(&mut diff, backend, &proposal_queue, &[])
            .map_err(|e| match e {
                crate::group::errors::ApplyProposalsError::LibraryError(e) => e.into(),
                crate::group::errors::ApplyProposalsError::MissingLeafNode => {
                    CreateCommitError::OwnKeyNotFound
                }
            })?;
        if apply_proposals_values.self_removed && params.commit_type() != CommitType::External {
            return Err(CreateCommitError::CannotRemoveSelf);
        }

        // Update keys in the leaf.
        if params.commit_type() == CommitType::External {
            // If this is an external commit we add a fresh leaf to the diff.
            // Generate a KeyPackageBundle to generate a payload from for later
            // path generation.
            let key_package = KeyPackage::create(
                CryptoConfig {
                    ciphersuite,
                    version: self.version(),
                },
                backend,
                params.credential_bundle(),
                vec![],
                vec![],
            )
            .map_err(|_| LibraryError::custom("Unexpected KeyPackage error"))?;

            let mut leaf_node: OpenMlsLeafNode = key_package.into();
            leaf_node.set_leaf_index(own_leaf_index);
            diff.add_leaf(leaf_node)
                .map_err(|_| LibraryError::custom("Tree full: cannot add more members"))?;
        }

        let serialized_group_context = self
            .group_context
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let path_processing_result =
            // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || params.force_self_update()
            {
                if params.commit_type() != CommitType::External {
                    // If we're in the tree, we rekey our existing leaf.
                    let own_diff_leaf = diff
                        .own_leaf_mut()
                        .map_err(|_| LibraryError::custom("Unable to get own leaf from diff"))?;
                    own_diff_leaf.rekey(
                        self.group_id(),
                        self.ciphersuite,
                        ProtocolVersion::default(), // XXX: openmls/openmls#1065
                        params.credential_bundle(),
                        backend,
                    )?;
                }

                // Derive and apply an update path based on the previously
                // generated new leaf.
                let (plain_path, commit_secret) = diff.apply_own_update_path(
                    backend,
                    ciphersuite,
                    self.group_id().clone(),
                    params.credential_bundle(),
                )?;

                // Encrypt the path to the correct recipient nodes.
                let encrypted_path = diff.encrypt_path(
                    backend,
                    self.ciphersuite(),
                    &plain_path,
                    &serialized_group_context,
                    &apply_proposals_values.exclusion_list(),
                );
                let leaf_node = diff.own_leaf().map_err(|_| LibraryError::custom("Couldn't find own leaf"))?.clone();
                let encrypted_path = UpdatePath::new(leaf_node.into(),  encrypted_path);
                PathProcessingResult {
                    commit_secret: Some(commit_secret),
                    encrypted_path: Some(encrypted_path),
                    plain_path: Some(plain_path),
                }
            } else {
                // If path is not needed, return empty path processing results
                PathProcessingResult::default()
            };

        let sender = match params.commit_type() {
            CommitType::External => Sender::NewMemberCommit,
            CommitType::Member => Sender::build_member(self.own_leaf_index()),
        };

        // Keep a copy of the update path key package
        let commit_update_leaf_node = path_processing_result
            .encrypted_path
            .as_ref()
            .map(|update| update.leaf_node().clone());

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list,
            path: path_processing_result.encrypted_path,
        };

        // Create provisional group state
        let mut provisional_epoch = self.group_context.epoch();
        provisional_epoch.increment();

        // Build AuthenticatedContent
        let mut commit = AuthenticatedContent::commit(
            *params.framing_parameters(),
            sender,
            commit,
            params.credential_bundle(),
            self.context(),
            backend,
        )?;

        // Calculate the confirmed transcript hash
        let confirmed_transcript_hash = update_confirmed_transcript_hash(
            ciphersuite,
            backend,
            // It is ok to a library error here, because we know the PublicMessage contains a
            // Commit
            &ConfirmedTranscriptHashInput::try_from(&commit)
                .map_err(|_| LibraryError::custom("PublicMessage did not contain a commit"))?,
            &self.interim_transcript_hash,
        )?;

        // Calculate tree hash
        let tree_hash = diff.compute_tree_hashes(backend, ciphersuite)?;

        // Calculate group context
        let provisional_group_context = GroupContext::new(
            ciphersuite,
            self.group_context.group_id().clone(),
            provisional_epoch,
            tree_hash.clone(),
            confirmed_transcript_hash.clone(),
            self.group_context.extensions(),
        );

        let joiner_secret = JoinerSecret::new(
            backend,
            path_processing_result.commit_secret,
            self.group_epoch_secrets().init_secret(),
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // Create group secrets for later use, so we can afterwards consume the
        // `joiner_secret`.
        let plaintext_secrets = PlaintextSecret::from_plain_update_path(
            &diff,
            &joiner_secret,
            apply_proposals_values.invitation_list,
            path_processing_result.plain_path.as_deref(),
            &apply_proposals_values.presharedkeys,
            backend,
        )?;

        // Prepare the PskSecret
        let psk_secret =
            PskSecret::new(ciphersuite, backend, &apply_proposals_values.presharedkeys)?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)?;

        let serialized_provisional_group_context = provisional_group_context
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let welcome_secret = key_schedule
            .welcome(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        key_schedule
            .add_context(backend, &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(backend)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(backend, &confirmed_transcript_hash)
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Set the confirmation tag
        commit.set_confirmation_tag(confirmation_tag.clone());

        // Check if new members were added and, if so, create welcome messages
        let welcome_option = if !plaintext_secrets.is_empty() {
            // Create the ratchet tree extension if necessary
            let other_extensions: Vec<Extension> = if self.use_ratchet_tree_extension {
                vec![Extension::RatchetTree(RatchetTreeExtension::new(
                    diff.export_nodes(),
                ))]
            } else {
                Vec::new()
            };
            // Create to-be-signed group info.
            let group_info_tbs = {
                let group_context = GroupContext::new(
                    ciphersuite,
                    provisional_group_context.group_id().clone(),
                    provisional_group_context.epoch(),
                    tree_hash,
                    confirmed_transcript_hash.clone(),
                    self.group_context_extensions(),
                );

                GroupInfoTBS::new(
                    group_context,
                    &other_extensions,
                    confirmation_tag.clone(),
                    diff.own_leaf_index(),
                )
            };
            // Sign to-be-signed group info.
            let group_info = group_info_tbs.sign(backend, params.credential_bundle())?;

            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret
                .derive_welcome_key_nonce(backend)
                .map_err(LibraryError::unexpected_crypto_error)?;
            let encrypted_group_info = welcome_key
                .aead_seal(
                    backend,
                    &group_info
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?,
                    &[],
                    &welcome_nonce,
                )
                .map_err(LibraryError::unexpected_crypto_error)?;
            // Encrypt group secrets
            let secrets = plaintext_secrets
                .into_iter()
                .map(|pts| pts.encrypt(backend, ciphersuite))
                .collect();
            // Create welcome message
            let welcome = Welcome::new(
                ProtocolVersion::Mls10,
                self.ciphersuite,
                secrets,
                encrypted_group_info,
            );
            Some(welcome)
        } else {
            None
        };

        let provisional_interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            backend,
            &InterimTranscriptHashInput::from(&confirmation_tag),
            &confirmed_transcript_hash,
        )?;

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.leaf_count(),
                own_leaf_index,
            );

        let staged_commit_state = MemberStagedCommitState::new(
            provisional_group_context,
            provisional_group_epoch_secrets,
            provisional_message_secrets,
            provisional_interim_transcript_hash,
            diff.into_staged_diff(backend, ciphersuite)?,
        );
        let staged_commit = StagedCommit::new(
            proposal_queue,
            StagedCommitState::GroupMember(Box::new(staged_commit_state)),
            commit_update_leaf_node,
        );

        Ok(CreateCommitResult {
            commit,
            welcome_option,
            staged_commit,
        })
    }

    /// Returns the leftmost free leaf index.
    ///
    /// For External Commits of the "resync" type, this returns the index
    /// of the sender.
    ///
    /// The proposals must be validated before calling this function.
    pub(crate) fn free_leaf_index<'a>(
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
}
