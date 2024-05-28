use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};

pub(super) use crate::{
    framing::mls_content::FramedContentBody,
    group::{GroupContext, ProposalStore, QueuedProposal},
    storage::OpenMlsProvider,
    versions::ProtocolVersion,
};

use super::{
    mls_auth_content::AuthenticatedContent, ApplicationMessage, GroupId, Message, PrivateMessageIn,
    ProcessMessageError, ProcessedMessage, ProcessedMessageContent, Proposal, PublicGroup,
    PublicMessageIn, Sender, StageCommitError, StagedCommit, UnverifiedMessage, ValidationError,
};

/// We use different groups.
/// This is a common trait for common functions that are implemented differently.
///
/// This trait only includes internal functions.
/// The [`GroupOperations`] trait includes public functions.
pub(crate) trait Group: GroupOperations {
    fn message_from_public(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        public_message: PublicMessageIn,
    ) -> Result<Message, ValidationError>;

    fn message_from_private(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        message: PrivateMessageIn,
    ) -> Result<Message, ValidationError>;

    fn public_group(&self) -> &PublicGroup;

    /// Stages a commit message that was sent by another group member.
    /// This function does the following:
    ///  - Applies the proposals covered by the commit to the tree
    ///  - Applies the (optional) update path to the tree
    ///  - Updates the [`GroupContext`]
    ///
    /// A similar function to this exists in [`CoreGroup`], which in addition
    /// does the following:
    ///  - Decrypts and derives the path secrets
    ///  - Initializes the key schedule for epoch rollover
    ///  - Verifies the confirmation tag
    ///
    /// Returns a [`StagedCommit`] that can be inspected and later merged into
    /// the group state either with [`CoreGroup::merge_commit()`] or
    /// [`PublicGroup::merge_diff()`] This function does the following checks:
    fn stage_commit(
        &self,
        mls_content: &AuthenticatedContent,
        proposal_store: &ProposalStore,
        provider: &impl OpenMlsProvider,
    ) -> Result<StagedCommit, StageCommitError>;

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    fn process_unverified_message<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        unverified_message: UnverifiedMessage,
        proposal_store: &ProposalStore,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let (content, credential) =
            unverified_message.verify(self.ciphersuite(), provider, self.version())?;

        match content.sender() {
            Sender::Member(_) | Sender::NewMemberCommit | Sender::NewMemberProposal => {
                let sender = content.sender().clone();
                let authenticated_data = content.authenticated_data().to_owned();

                let content = match content.content() {
                    FramedContentBody::Application(application_message) => {
                        ProcessedMessageContent::ApplicationMessage(ApplicationMessage::new(
                            application_message.as_slice().to_owned(),
                        ))
                    }
                    FramedContentBody::Proposal(_) => {
                        let proposal = Box::new(QueuedProposal::from_authenticated_content_by_ref(
                            self.ciphersuite(),
                            provider.crypto(),
                            content,
                        )?);

                        if matches!(sender, Sender::NewMemberProposal) {
                            ProcessedMessageContent::ExternalJoinProposalMessage(proposal)
                        } else {
                            ProcessedMessageContent::ProposalMessage(proposal)
                        }
                    }
                    FramedContentBody::Commit(_) => {
                        let staged_commit = self.stage_commit(
                            &content,
                            proposal_store,
                            // old_epoch_keypairs,
                            // leaf_node_keypairs,
                            provider,
                        )?;
                        ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
                    }
                };

                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.context().epoch(),
                    sender,
                    authenticated_data,
                    content,
                    credential,
                ))
            }
            Sender::External(_) => {
                let sender = content.sender().clone();
                let data = content.authenticated_data().to_owned();
                match content.content() {
                    FramedContentBody::Application(_) => {
                        Err(ProcessMessageError::UnauthorizedExternalApplicationMessage)
                    }
                    FramedContentBody::Proposal(Proposal::Remove(_)) => {
                        let content = ProcessedMessageContent::ProposalMessage(Box::new(
                            QueuedProposal::from_authenticated_content_by_ref(
                                self.ciphersuite(),
                                provider.crypto(),
                                content,
                            )?,
                        ));
                        Ok(ProcessedMessage::new(
                            self.group_id().clone(),
                            self.context().epoch(),
                            sender,
                            data,
                            content,
                            credential,
                        ))
                    }
                    // TODO #151/#106
                    FramedContentBody::Proposal(_) => {
                        Err(ProcessMessageError::UnsupportedProposalType)
                    }
                    FramedContentBody::Commit(_) => unimplemented!(),
                }
            }
        }
    }
}

/// Common operations on a group.
pub trait GroupOperations {
    /// Returns the group's ciphersuite.
    fn ciphersuite(&self) -> Ciphersuite;

    /// Returns the protocol version.
    fn version(&self) -> ProtocolVersion;

    /// REturns the group id.
    fn group_id(&self) -> &GroupId;

    /// Returns the group context.
    fn context(&self) -> &GroupContext;
}
