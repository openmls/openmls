//! Defines the `CreateCommit` trait and its implementation for `MlsGroup`.

use super::*;
use crate::{credentials::CredentialWithKey, treesync::LeafNodeParameters};

/// Can be used to denote the type of a commit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum CommitType {
    External(CredentialWithKey),
    Member,
}

pub(crate) struct CreateCommitParams<'a> {
    framing_parameters: Option<FramingParameters<'a>>,
    credential_with_key: CredentialWithKey,

    inline_proposals: Vec<Proposal>,          // Optional
    force_self_update: bool,                  // Optional
    leaf_node_parameters: LeafNodeParameters, // Optional
}

pub(crate) struct TempBuilderCCPM0 {}

pub(crate) struct CreateCommitParamsBuilder<'a> {
    ccp: CreateCommitParams<'a>,
}

impl TempBuilderCCPM0 {
    pub(crate) fn external_commit(
        self,
        credential_with_key: CredentialWithKey,
        framing_parameters: FramingParameters,
    ) -> CreateCommitParamsBuilder {
        CreateCommitParamsBuilder {
            ccp: CreateCommitParams {
                framing_parameters: Some(framing_parameters),
                credential_with_key,

                // defaults:
                inline_proposals: vec![],
                force_self_update: true,
                leaf_node_parameters: LeafNodeParameters::default(),
            },
        }
    }
}

impl<'a> CreateCommitParamsBuilder<'a> {
    pub(crate) fn leaf_node_parameters(mut self, leaf_node_parameters: LeafNodeParameters) -> Self {
        self.ccp.leaf_node_parameters = leaf_node_parameters;
        self
    }
    pub(crate) fn build(self) -> CreateCommitParams<'a> {
        self.ccp
    }
}

impl CreateCommitParams<'_> {
    pub(crate) fn builder() -> TempBuilderCCPM0 {
        TempBuilderCCPM0 {}
    }
    pub(crate) fn inline_proposals(&self) -> &[Proposal] {
        &self.inline_proposals
    }
    pub(crate) fn set_inline_proposals(&mut self, inline_proposals: Vec<Proposal>) {
        self.inline_proposals = inline_proposals;
    }
    pub(crate) fn force_self_update(&self) -> bool {
        self.force_self_update
    }
    pub(crate) fn credential_with_key(&self) -> &CredentialWithKey {
        &self.credential_with_key
    }
    pub(crate) fn leaf_node_parameters(&self) -> &LeafNodeParameters {
        &self.leaf_node_parameters
    }
}

impl MlsGroup {
    pub(crate) fn create_external_commit<Provider: OpenMlsProvider>(
        &mut self,
        params: CreateCommitParams,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<CreateCommitResult, CreateCommitError> {
        // We  are building an external commit. This means we have to pull the
        // framing parameters out of the create commit parameteres instead of the group. Since
        // these are set together with the group mode, we can be sure that this is `Some(..)` (see
        // [`TempBuilderCCPM0::external_commit`].
        let framing_parameters = params.framing_parameters.unwrap();
        let commit_type = CommitType::External(params.credential_with_key().clone());

        let ciphersuite = self.ciphersuite();

        let sender = match commit_type {
            CommitType::External(_) => Sender::NewMemberCommit,
            CommitType::Member => Sender::build_member(self.own_leaf_index()),
        };

        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            provider.crypto(),
            sender.clone(),
            self.proposal_store(),
            params.inline_proposals(),
            self.own_leaf_index(),
        )
        .map_err(|e| match e {
            ProposalQueueError::LibraryError(e) => e.into(),
            ProposalQueueError::ProposalNotFound => CreateCommitError::MissingProposal,
            ProposalQueueError::UpdateFromExternalSender => {
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

        // ValSem113: All Proposals: The proposal type must be supported by all
        // members of the group
        self.public_group
            .validate_proposal_type_support(&proposal_queue)?;
        // ValSem101
        // ValSem102
        // ValSem103
        // ValSem104
        self.public_group
            .validate_key_uniqueness(&proposal_queue, None)?;
        // ValSem105
        self.public_group.validate_add_proposals(&proposal_queue)?;
        // ValSem106
        // ValSem109
        self.public_group.validate_capabilities(&proposal_queue)?;
        // ValSem107
        // ValSem108
        self.public_group
            .validate_remove_proposals(&proposal_queue)?;
        self.public_group
            .validate_pre_shared_key_proposals(&proposal_queue)?;
        // Validate update proposals for member commits
        if let Sender::Member(sender_index) = &sender {
            // ValSem110
            // ValSem111
            // ValSem112
            self.public_group
                .validate_update_proposals(&proposal_queue, *sender_index)?;
        }

        // ValSem208
        // ValSem209
        self.public_group
            .validate_group_context_extensions_proposal(&proposal_queue)?;

        // Make a copy of the public group to apply proposals safely
        let mut diff = self.public_group.empty_diff();

        // Apply proposals to tree
        let apply_proposals_values =
            diff.apply_proposals(&proposal_queue, self.own_leaf_index())?;

        let path_computation_result =
            // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || params.force_self_update()
                || !params.leaf_node_parameters().is_empty()
            {
                // Process the path. This includes updating the provisional
                // group context by updating the epoch and computing the new
                // tree hash.
                diff.compute_path(
                    provider.rand(),
                    provider.crypto(),
                    self.own_leaf_index(),
                    apply_proposals_values.exclusion_list(),
                    &commit_type,
                    params.leaf_node_parameters(),
                    signer,
                    apply_proposals_values.extensions.clone()
                )?
            } else {
                // If path is not needed, update the group context and return
                // empty path processing results
                diff.update_group_context(provider.crypto(), apply_proposals_values.extensions.clone())?;
                PathComputationResult::default()
            };

        let update_path_leaf_node = path_computation_result
            .encrypted_path
            .as_ref()
            .map(|path| path.leaf_node().clone());

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list,
            path: path_computation_result.encrypted_path,
        };

        // Build AuthenticatedContent
        let mut authenticated_content = AuthenticatedContent::commit(
            framing_parameters,
            sender,
            commit,
            self.public_group.group_context(),
            signer,
        )?;

        // Update the confirmed transcript hash using the commit we just created.
        diff.update_confirmed_transcript_hash(provider.crypto(), &authenticated_content)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let joiner_secret = JoinerSecret::new(
            provider.crypto(),
            ciphersuite,
            path_computation_result.commit_secret,
            self.group_epoch_secrets().init_secret(),
            &serialized_provisional_group_context,
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // Prepare the PskSecret
        let psk_secret = {
            let psks = load_psks(
                provider.storage(),
                &self.resumption_psk_store,
                &apply_proposals_values.presharedkeys,
            )?;

            PskSecret::new(provider.crypto(), ciphersuite, psks)?
        };

        // Create key schedule
        let mut key_schedule =
            KeySchedule::init(ciphersuite, provider.crypto(), &joiner_secret, psk_secret)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let welcome_secret = key_schedule
            .welcome(provider.crypto(), self.ciphersuite())
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        key_schedule
            .add_context(provider.crypto(), &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(provider.crypto(), self.ciphersuite())
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(
                provider.crypto(),
                self.ciphersuite(),
                diff.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Set the confirmation tag
        authenticated_content.set_confirmation_tag(confirmation_tag.clone());

        diff.update_interim_transcript_hash(
            ciphersuite,
            provider.crypto(),
            confirmation_tag.clone(),
        )?;

        // only computes the group info if necessary
        let group_info = if !apply_proposals_values.invitation_list.is_empty()
            || self.configuration().use_ratchet_tree_extension
        {
            // Create the ratchet tree extension if necessary
            let external_pub = provisional_epoch_secrets
                .external_secret()
                .derive_external_keypair(provider.crypto(), ciphersuite)
                .map_err(LibraryError::unexpected_crypto_error)?
                .public;
            let external_pub_extension =
                Extension::ExternalPub(ExternalPubExtension::new(external_pub.into()));
            let other_extensions: Extensions = if self.configuration().use_ratchet_tree_extension {
                Extensions::from_vec(vec![
                    Extension::RatchetTree(RatchetTreeExtension::new(diff.export_ratchet_tree())),
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
                    confirmation_tag,
                    self.own_leaf_index(),
                )
            };
            // Sign to-be-signed group info.
            Some(group_info_tbs.sign(signer)?)
        } else {
            None
        };

        // Check if new members were added and, if so, create welcome messages
        let welcome_option = if !apply_proposals_values.invitation_list.is_empty() {
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret
                .derive_welcome_key_nonce(provider.crypto(), self.ciphersuite())
                .map_err(LibraryError::unexpected_crypto_error)?;
            let encrypted_group_info = welcome_key
                .aead_seal(
                    provider.crypto(),
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

            // Create group secrets for later use, so we can afterwards consume the
            // `joiner_secret`.
            let encrypted_secrets = diff.encrypt_group_secrets(
                &joiner_secret,
                apply_proposals_values.invitation_list,
                path_computation_result.plain_path.as_deref(),
                &apply_proposals_values.presharedkeys,
                &encrypted_group_info,
                provider.crypto(),
                self.own_leaf_index(),
            )?;

            // Create welcome message
            let welcome = Welcome::new(self.ciphersuite(), encrypted_secrets, encrypted_group_info);
            Some(welcome)
        } else {
            None
        };

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.tree_size(),
                self.own_leaf_index(),
            );

        let staged_commit_state = MemberStagedCommitState::new(
            provisional_group_epoch_secrets,
            provisional_message_secrets,
            diff.into_staged_diff(provider.crypto(), ciphersuite)?,
            path_computation_result.new_keypairs,
            // The committer is not allowed to include their own update
            // proposal, so there is no extra keypair to store here.
            None,
            update_path_leaf_node,
        );
        let staged_commit = StagedCommit::new(
            proposal_queue,
            StagedCommitState::GroupMember(Box::new(staged_commit_state)),
        );

        Ok(CreateCommitResult {
            commit: authenticated_content,
            welcome_option,
            staged_commit,
            group_info: group_info.filter(|_| self.configuration().use_ratchet_tree_extension),
        })
    }
}
