use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::Serialize;

use crate::{
    ciphersuite::OpenMlsSignaturePublicKey,
    credentials::CredentialWithKey,
    error::LibraryError,
    framing::{
        mls_auth_content::AuthenticatedContent, private_message_in::PrivateMessageIn,
        public_message_in::PublicMessageIn, Message, ProcessedMessage, ProtocolMessage, Sender,
        SenderContext, UnverifiedMessage,
    },
    group::{
        core_group::{proposals::ProposalStore, staged_commit::StagedCommitState},
        errors::ValidationError,
        mls_group::errors::ProcessMessageError,
        past_secrets::MessageSecretsStore,
        processing::message_from_protocol_message,
        traits::Group,
        StagedCommit,
    },
    storage::OpenMlsProvider,
};

use super::{staged_commit::PublicStagedCommitState, PublicGroup};

impl PublicGroup {
    /// This function is used to parse messages from the DS. It checks for
    /// syntactic errors and does semantic validation as well. It returns a
    /// [ProcessedMessage] enum.
    ///
    /// ProtocolMessage -> Message -> UnverifiedMessage -> ProcessedMessage
    pub fn process_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let protocol_message = message.into();
        let message = message_from_protocol_message(self, provider.crypto(), protocol_message)?;
        let unverified_message = self
            .parse_message(message, None)
            .map_err(ProcessMessageError::from)?;
        self.process_unverified_message(provider, unverified_message, &self.proposal_store)
    }
}

impl PublicGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [PrivateMessage] message, it will be decrypted.
    /// Returns an [UnverifiedMessage] that can be inspected and later processed in
    /// [Self::process_unverified_message()].
    pub(crate) fn parse_message<'a>(
        &self,
        message: Message,
        message_secrets_store_option: impl Into<Option<&'a MessageSecretsStore>>,
    ) -> Result<UnverifiedMessage, ValidationError> {
        let message_secrets_store_option = message_secrets_store_option.into();

        // Extract the credential if the sender is a member or a new member.
        // External senders are not supported yet #106/#151.
        let CredentialWithKey {
            credential,
            signature_key,
        } = message.credential(
            self.treesync(),
            message_secrets_store_option
                .map(|store| store.leaves_for_epoch(message.verifiable_content().epoch()))
                .unwrap_or_default(),
            self.group_context().extensions().external_senders(),
        )?;
        let signature_public_key = OpenMlsSignaturePublicKey::from_signature_key(
            signature_key,
            self.ciphersuite().signature_algorithm(),
        );

        // For commit messages, we need to check if the sender is a member or a
        // new member and set the tree position accordingly.
        let sender_context = match message.sender() {
            Sender::Member(leaf_index) => Some(SenderContext::Member((
                self.group_id().clone(),
                *leaf_index,
            ))),
            Sender::NewMemberCommit => Some(SenderContext::ExternalCommit((
                self.group_id().clone(),
                self.treesync().free_leaf_index(),
            ))),
            Sender::External(_) | Sender::NewMemberProposal => None,
        };

        Ok(UnverifiedMessage::from_message(
            message,
            credential,
            signature_public_key,
            sender_context,
        ))
    }
}

impl Group for PublicGroup {
    fn message_from_public(
        &mut self,
        _: &impl OpenMlsCrypto,
        public_message: PublicMessageIn,
    ) -> Result<Message, ValidationError> {
        let verifiable_content = public_message.into_verifiable_content(
            self.group_context()
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
        );

        Ok(Message { verifiable_content })
    }

    fn message_from_private(
        &mut self,
        _: &impl OpenMlsCrypto,
        _: PrivateMessageIn,
    ) -> Result<Message, ValidationError> {
        Err(ValidationError::LibraryError(LibraryError::custom(
            "This function must never be called in public groups",
        )))
    }

    fn ciphersuite(&self) -> openmls_traits::prelude::openmls_types::Ciphersuite {
        self.group_context.ciphersuite()
    }

    fn version(&self) -> crate::versions::ProtocolVersion {
        self.group_context.protocol_version()
    }

    fn group_id(&self) -> &crate::group::GroupId {
        self.group_context.group_id()
    }

    fn context(&self) -> &crate::group::GroupContext {
        todo!()
    }

    fn stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        provider: &impl OpenMlsProvider,
    ) -> Result<crate::group::StagedCommit, crate::group::StageCommitError> {
        let (commit, proposal_queue, sender_index) =
            self.validate_commit(mls_content, proposal_store, provider.crypto())?;

        let staged_diff = self.stage_diff(
            mls_content,
            &proposal_queue,
            sender_index,
            provider.crypto(),
        )?;
        let staged_state = PublicStagedCommitState {
            staged_diff,
            update_path_leaf_node: commit.path.as_ref().map(|p| p.leaf_node().clone()),
        };

        let staged_commit_state = StagedCommitState::PublicState(Box::new(staged_state));

        Ok(StagedCommit::new(proposal_queue, staged_commit_state))
    }

    fn public_group(&self) -> &PublicGroup {
        self
    }
}
