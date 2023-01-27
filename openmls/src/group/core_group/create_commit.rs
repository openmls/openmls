use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    ciphersuite::signable::Signable,
    group::{
        core_group::*, errors::CreateCommitError,
        public_group::diff::process_path::PathProcessingResult,
    },
    versions::ProtocolVersion,
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    proposals::ProposalQueue,
    staged_commit::{MemberStagedCommitState, StagedCommit, StagedCommitState},
};

impl CoreGroup {
    pub(crate) fn create_commit<KeyStore: OpenMlsKeyStore>(
        &self,
        params: CreateCommitParams,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<CreateCommitResult, CreateCommitError<KeyStore::Error>> {
        let ciphersuite = self.ciphersuite();

        let sender = match params.commit_type() {
            CommitType::External => Sender::NewMemberCommit,
            CommitType::Member => Sender::build_member(self.own_leaf_index()),
        };

        // If this is a "resync" external commit, it should contain a
        // `remove` proposal with the index of our previous self in the
        // group.

        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            backend,
            sender.clone(),
            params.proposal_store(),
            params.inline_proposals(),
            self.own_leaf_index(),
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

        // Validate the proposals by doing the following checks:

        // ValSem100
        // ValSem101
        // ValSem102
        // ValSem103
        // ValSem104
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

        // Make a copy of the public group to apply proposals safely
        let mut diff = self.public_group.empty_diff();

        // Apply proposals to tree
        let apply_proposals_values =
            diff.apply_proposals(&proposal_queue, self.own_leaf_index())?;
        if apply_proposals_values.self_removed && params.commit_type() != CommitType::External {
            return Err(CreateCommitError::CannotRemoveSelf);
        }

        let serialized_group_context = self
            .context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let path_processing_result =
            // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || params.force_self_update()
            {
                diff.process_path(backend, self.own_leaf_index(), apply_proposals_values.exclusion_list(), params.commit_type(), params.credential_bundle())?
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
        let mut provisional_epoch = self.context().epoch();
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

        diff.update_group_context(ciphersuite, backend, &commit)?;

        let joiner_secret = JoinerSecret::new(
            backend,
            path_processing_result.commit_secret,
            self.group_epoch_secrets().init_secret(),
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // Create group secrets for later use, so we can afterwards consume the
        // `joiner_secret`.
        let encrypted_secrets = diff.encrypt_group_secrets(
            &joiner_secret,
            apply_proposals_values.invitation_list,
            path_processing_result.plain_path.as_deref(),
            &apply_proposals_values.presharedkeys,
            backend,
            self.own_leaf_index(),
        )?;

        // Prepare the PskSecret
        let psk_secret =
            PskSecret::new(ciphersuite, backend, &apply_proposals_values.presharedkeys)?;

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)?;

        let serialized_provisional_group_context = diff
            .group_context()
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
            .tag(backend, diff.group_context().confirmed_transcript_hash())
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Set the confirmation tag
        commit.set_confirmation_tag(confirmation_tag.clone());

        diff.update_interim_transcript_hash(ciphersuite, backend, confirmation_tag)?;

        // only computes the group info if necessary
        let group_info = if !encrypted_secrets.is_empty() || self.use_ratchet_tree_extension {
            // Create the ratchet tree extension if necessary
            let external_pub = provisional_epoch_secrets
                .external_secret()
                .derive_external_keypair(backend.crypto(), ciphersuite)
                .public;
            let external_pub_extension =
                Extension::ExternalPub(ExternalPubExtension::new(external_pub.into()));
            let other_extensions: Extensions = if self.use_ratchet_tree_extension {
                Extensions::from_vec(vec![
                    Extension::RatchetTree(RatchetTreeExtension::new(diff.export_nodes())),
                    external_pub_extension,
                ])?
            } else {
                Extensions::single(external_pub_extension)
            };

            // Create to-be-signed group info.
            let group_info_tbs = {
                GroupInfoTBS::new(
                    diff.group_context().clone(),
                    other_extensions,
                    confirmation_tag.clone(),
                    self.own_leaf_index(),
                )
            };
            // Sign to-be-signed group info.
            Some(group_info_tbs.sign(backend, params.credential_bundle().signature_private_key())?)
        } else {
            None
        };

        // Check if new members were added and, if so, create welcome messages
        let welcome_option = if !encrypted_secrets.is_empty() {
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret
                .derive_welcome_key_nonce(backend)
                .map_err(LibraryError::unexpected_crypto_error)?;
            let encrypted_group_info = welcome_key
                .aead_seal(
                    backend,
                    group_info
                        .as_ref()
                        .ok_or_else(|| LibraryError::custom("GroupInfo was not computed"))?
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?
                        .as_slice(),
                    &[],
                    &welcome_nonce,
                )
                .map_err(LibraryError::unexpected_crypto_error)?;
            // Create welcome message
            let welcome = Welcome::new(
                ProtocolVersion::Mls10,
                self.ciphersuite(),
                encrypted_secrets,
                encrypted_group_info,
            );
            Some(welcome)
        } else {
            None
        };

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.leaf_count(),
                self.own_leaf_index(),
            );

        let staged_commit_state = MemberStagedCommitState::new(
            provisional_group_epoch_secrets,
            provisional_message_secrets,
            diff.into_staged_diff(backend, ciphersuite)?,
            path_processing_result.new_keypairs,
            // The committer is not allowed to include their own update
            // proposal, so there is no extra keypair to store here.
            None,
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
            group_info: group_info.filter(|_| self.use_ratchet_tree_extension),
        })
    }
}
