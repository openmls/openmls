//! Processing functions of an [`MlsGroup`] for incoming messages.

use std::mem;

use core_group::staged_commit::StagedCommit;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::{signatures::Signer, storage::StorageProvider as _};

use crate::storage::OpenMlsProvider;
use crate::versions::ProtocolVersion;
use crate::{
    group::core_group::create_commit_params::CreateCommitParams, messages::group_info::GroupInfo,
};

use crate::group::errors::MergeCommitError;

use self::traits::{Group, GroupOperations};

use super::{errors::ProcessMessageError, *};

impl MlsGroup {
    /// Parses incoming messages from the DS. Checks for syntactic errors and
    /// makes some semantic checks as well. If the input is an encrypted
    /// message, it will be decrypted. This processing function does syntactic
    /// and semantic validation of the message. It returns a [ProcessedMessage]
    /// enum.
    ///
    /// # Errors:
    /// Returns an [`ProcessMessageError`] when the validation checks fail
    /// with the exact reason of the failure.
    pub fn process_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        // Make sure we are still a member of the group
        if !self.is_active() {
            return Err(ProcessMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        let protocol_message = message.into();

        // Check that handshake messages are compatible with the incoming wire format policy
        if !protocol_message.is_external()
            && protocol_message.is_handshake_message()
            && !self
                .configuration()
                .wire_format_policy()
                .incoming()
                .is_compatible_with(protocol_message.wire_format())
        {
            return Err(ProcessMessageError::IncompatibleWireFormat);
        }

        // Parse the message
        // Check for syntactic errors and check semantic validation as well.
        // If the input is a [PrivateMessage] message, it will be decrypted.
        let message = message_from_protocol_message(self, provider.crypto(), protocol_message)?;

        let unverified_message = self
            .group
            .public_group()
            .parse_message(message, &self.group.message_secrets_store)
            .map_err(ProcessMessageError::from)?;

        self.process_unverified_message(provider, unverified_message, &self.proposal_store)
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        proposal: QueuedProposal,
    ) -> Result<(), Storage::Error> {
        storage.queue_proposal(self.group_id(), &proposal.proposal_reference(), &proposal)?;
        // Store the proposal in in the internal ProposalStore
        self.proposal_store.add(proposal);

        Ok(())
    }

    /// Creates a Commit message that covers the pending proposals that are
    /// currently stored in the group's [ProposalStore]. The Commit message is
    /// created even if there are no valid pending proposals.
    ///
    /// Returns an error if there is a pending commit. Otherwise it returns a
    /// tuple of `Commit, Option<Welcome>, Option<GroupInfo>`, where `Commit`
    /// and [`Welcome`] are MlsMessages of the type [`MlsMessageOut`].
    ///
    /// [`Welcome`]: crate::messages::Welcome
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn commit_to_pending_proposals<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        CommitToPendingProposalsError<Provider::StorageError>,
    > {
        self.is_operational()?;

        // Create Commit over all pending proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .build();
        let create_commit_result = self.group.create_commit(params, provider, signer)?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));
        provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(CommitToPendingProposalsError::StorageError)?;

        Ok((
            mls_message,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }

    /// Merge a [StagedCommit] into the group after inspection. As this advances
    /// the epoch of the group, it also clears any pending commits.
    pub fn merge_staged_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>> {
        // Check if we were removed from the group
        if staged_commit.self_removed() {
            self.group_state = MlsGroupState::Inactive;
        }
        provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(MergeCommitError::StorageError)?;

        // Merge staged commit
        self.group
            .merge_staged_commit(provider, staged_commit, &mut self.proposal_store)?;

        // Extract and store the resumption psk for the current epoch
        let resumption_psk = self.group.group_epoch_secrets().resumption_psk();
        self.group
            .resumption_psk_store
            .add(self.group.context().epoch(), resumption_psk.clone());

        // Delete own KeyPackageBundles
        self.own_leaf_nodes.clear();
        provider
            .storage()
            .clear_own_leaf_nodes(self.group_id())
            .map_err(MergeCommitError::StorageError)?;

        // Delete a potential pending commit
        self.clear_pending_commit(provider.storage())
            .map_err(MergeCommitError::StorageError)?;

        Ok(())
    }

    /// Merges the pending [`StagedCommit`] if there is one, and
    /// clears the field by setting it to `None`.
    pub fn merge_pending_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>> {
        match &self.group_state {
            MlsGroupState::PendingCommit(_) => {
                let old_state = mem::replace(&mut self.group_state, MlsGroupState::Operational);
                if let MlsGroupState::PendingCommit(pending_commit_state) = old_state {
                    self.merge_staged_commit(provider, (*pending_commit_state).into())?;
                }
                Ok(())
            }
            MlsGroupState::Inactive => Err(MlsGroupStateError::UseAfterEviction)?,
            MlsGroupState::Operational => Ok(()),
        }
    }
}

impl Group for MlsGroup {
    fn message_from_public(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        public_message: PublicMessageIn,
    ) -> Result<Message, ValidationError> {
        // If the message is older than the current epoch, we need to fetch the correct secret tree first.
        let message_secrets = self
            .group
            .message_secrets_for_epoch(public_message.epoch())
            .map_err(|e| match e {
                SecretTreeError::TooDistantInThePast => ValidationError::NoPastEpochData,
                _ => LibraryError::custom(
                    "Unexpected error while retrieving message secrets for epoch.",
                )
                .into(),
            })?;

        if public_message.sender().is_member() {
            // Verify the membership tag. This needs to be done explicitly for PublicMessage messages,
            // it is implicit for PrivateMessage messages (because the encryption can only be known by members).
            public_message.verify_membership(
                crypto,
                self.ciphersuite(),
                message_secrets.membership_key(),
                message_secrets.serialized_context(),
            )?;
        }

        let verifiable_content =
            public_message.into_verifiable_content(message_secrets.serialized_context().to_vec());

        Ok(Message { verifiable_content })
    }

    fn message_from_private(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphertext: PrivateMessageIn,
    ) -> Result<Message, ValidationError> {
        let sender_ratchet_configuration =
            self.configuration().sender_ratchet_configuration().clone();

        // If the message is older than the current epoch, we need to fetch the correct secret tree first
        let ciphersuite = self.ciphersuite();
        let message_secrets = self
            .group
            .message_secrets_and_leaves_mut(ciphertext.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let sender_data = ciphertext.sender_data(message_secrets, crypto, ciphersuite)?;
        let message_secrets = self
            .group
            .message_secrets_mut(ciphertext.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let verifiable_content = ciphertext.decrypt_to_verifiable_content(
            ciphersuite,
            crypto,
            message_secrets,
            sender_data.leaf_index,
            &sender_ratchet_configuration,
            sender_data,
        )?;

        Ok(Message { verifiable_content })
    }

    fn stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        provider: &impl OpenMlsProvider,
    ) -> Result<StagedCommit, StageCommitError> {
        // If this is a commit, we need to load the private key material we need for decryption.
        let (old_epoch_keypairs, leaf_node_keypairs) =
            if let ContentType::Commit = mls_content.content().content_type() {
                self.group
                    .read_decryption_keypairs(provider, &self.own_leaf_nodes)?
            } else {
                (vec![], vec![])
            };

        self.group.stage_commit(
            mls_content,
            proposal_store,
            old_epoch_keypairs,
            leaf_node_keypairs,
            provider,
        )
    }

    fn public_group(&self) -> &PublicGroup {
        self.group.public_group()
    }
}

impl GroupOperations for MlsGroup {
    fn ciphersuite(&self) -> Ciphersuite {
        self.group.ciphersuite()
    }

    fn version(&self) -> ProtocolVersion {
        self.group.version()
    }

    fn group_id(&self) -> &GroupId {
        self.group.group_id()
    }

    fn context(&self) -> &GroupContext {
        self.group.context()
    }
}

/// Performs framing validation and, if necessary, decrypts the given message.
///
/// Returns the [`DecryptedMessage`] if processing is successful, or a
/// [`ValidationError`] if it is not.
pub(crate) fn message_from_protocol_message<G: Group>(
    group: &mut G,
    crypto: &impl OpenMlsCrypto,
    message: ProtocolMessage,
) -> Result<Message, ValidationError> {
    // Convert to Protocol message and check its validity.
    message.validate(group.public_group())?;

    match message {
        ProtocolMessage::PublicMessage(public_message) => {
            group.message_from_public(crypto, public_message)
        }
        ProtocolMessage::PrivateMessage(ciphertext) => {
            group.message_from_private(crypto, ciphertext)
        }
    }
}
