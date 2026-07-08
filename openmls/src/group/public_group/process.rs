//! This module contains the implementation of the processing functions for
//! public groups.

use openmls_traits::crypto::OpenMlsCrypto;
use tls_codec::Serialize;

use crate::{
    ciphersuite::OpenMlsSignaturePublicKey,
    credentials::{Credential, CredentialWithKey},
    error::LibraryError,
    framing::{
        mls_auth_content::AuthenticatedContent, mls_content::FramedContentBody, ApplicationMessage,
        DecryptedMessage, ProcessedMessage, ProcessedMessageContent, ProtocolMessage, Sender,
        SenderContext, UnverifiedMessage,
    },
    group::{
        errors::ValidationError, past_secrets::MessageSecretsStore, proposal_store::QueuedProposal,
        PublicProcessMessageError,
    },
    messages::proposals::Proposal,
};

#[cfg(feature = "extensions-draft")]
use crate::{
    group::{
        mls_group::processing::{committed_app_data_update_proposals, UnresolvedAppDataCommit},
        ResolveAppDataCommitError, StageCommitError, StagedCommit,
    },
    prelude::processing::{AppDataDictionaryUpdater, AppDataUpdates},
};

use super::PublicGroup;

impl PublicGroup {
    /// This function is used to parse messages from the DS.
    /// It checks for syntactic errors and makes some semantic checks as well.
    /// If the input is a [PrivateMessage] message, it will be decrypted.
    /// Returns an [UnverifiedMessage] that can be inspected and later processed in
    /// [Self::process_unverified_message()].
    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    ///  - ValSem004
    ///  - ValSem005
    ///  - ValSem006
    ///  - ValSem007
    ///  - ValSem009
    ///  - ValSem112
    ///  - ValSem245
    pub(crate) fn parse_message<'a>(
        &self,
        decrypted_message: DecryptedMessage,
        message_secrets_store_option: impl Into<Option<&'a MessageSecretsStore>>,
    ) -> Result<UnverifiedMessage, ValidationError> {
        let message_secrets_store_option = message_secrets_store_option.into();
        let verifiable_content = decrypted_message.verifiable_content();

        // Checks the following semantic validation:
        //  - ValSem004
        //  - ValSem005
        //  - ValSem009
        self.validate_verifiable_content(verifiable_content, message_secrets_store_option)?;

        let message_epoch = verifiable_content.epoch();

        // Depending on the epoch of the message, use the correct set of leaf nodes for getting the
        // credential and signature key for the member with given index.
        let look_up_credential_with_key = |leaf_node_index| {
            if message_epoch == self.group_context().epoch() {
                self.treesync()
                    .leaf(leaf_node_index)
                    .map(CredentialWithKey::from)
            } else if let Some(store) = message_secrets_store_option {
                // The message is from a past epoch, look up the member in the
                // past secrets store based on the epoch and sender's leaf
                // index.
                store
                    .leaves_for_epoch(message_epoch)
                    .get(&leaf_node_index)
                    .map(|&member| CredentialWithKey::from(member))
            } else {
                None
            }
        };

        // Extract the credential if the sender is a member or a new member.
        // Checks the following semantic validation:
        //  - ValSem112
        //  - ValSem245
        //  - Prepares ValSem246 by setting the right credential. The remainder
        //    of ValSem246 is validated as part of ValSem010.
        // External senders are not supported yet #106/#151.
        let CredentialWithKey {
            credential,
            signature_key,
        } = decrypted_message.credential(
            look_up_credential_with_key,
            self.group_context().extensions().external_senders(),
        )?;
        let signature_public_key = OpenMlsSignaturePublicKey::from_signature_key(
            signature_key,
            self.ciphersuite().signature_algorithm(),
        );

        // For commit messages, we need to check if the sender is a member or a
        // new member and set the tree position accordingly.
        let sender_context = match decrypted_message.sender() {
            Sender::Member(leaf_index) => Some(SenderContext::Member((
                self.group_id().clone(),
                *leaf_index,
            ))),
            Sender::NewMemberCommit => Some(SenderContext::ExternalCommit {
                group_id: self.group_id().clone(),
                leftmost_blank_index: self.treesync().free_leaf_index(),
                self_removes_in_store: self.proposal_store.self_removes(),
            }),
            Sender::External(_) | Sender::NewMemberProposal => None,
        };

        Ok(UnverifiedMessage::from_decrypted_message(
            decrypted_message,
            credential,
            signature_public_key,
            sender_context,
        ))
    }

    /// This function is used to parse messages from the DS. It checks for
    /// syntactic errors and does semantic validation as well. It returns a
    /// [ProcessedMessage] enum. Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    ///  - ValSem004
    ///  - ValSem005
    ///  - ValSem006
    ///  - ValSem007
    ///  - ValSem008
    ///  - ValSem009
    ///  - ValSem010
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
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
    ///    private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem244
    ///  - ValSem245
    ///  - ValSem246 (as part of ValSem010)
    ///
    #[cfg_attr(
        feature = "extensions-draft",
        doc = "A commit covering AppDataUpdate proposals is returned as\n\
        [`ProcessedMessageContent::UnresolvedAppDataCommit`], since the\n\
        application has to interpret the proposals before the commit can be\n\
        staged via [`PublicGroup::stage_app_data_commit()`]."
    )]
    pub fn process_message(
        &self,
        crypto: &impl OpenMlsCrypto,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, PublicProcessMessageError> {
        let protocol_message = message.into();
        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        self.validate_framing(&protocol_message)?;

        let decrypted_message = match protocol_message {
            ProtocolMessage::PrivateMessage(_) => {
                return Err(PublicProcessMessageError::IncompatibleWireFormat)
            }
            ProtocolMessage::PublicMessage(public_message) => {
                DecryptedMessage::from_inbound_public_message(
                    *public_message,
                    None,
                    self.group_context()
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?,
                    crypto,
                    self.ciphersuite(),
                )?
            }
        };

        let unverified_message = self
            .parse_message(decrypted_message, None)
            .map_err(PublicProcessMessageError::from)?;
        self.process_unverified_message(crypto, unverified_message)
    }

    #[cfg(feature = "extensions-draft")]
    /// Returns a new helper struct for updating the app data
    pub fn app_data_dictionary_updater(&self) -> AppDataDictionaryUpdater<'_> {
        AppDataDictionaryUpdater::new(self.group_context().app_data_dict())
    }

    /// Stages a Commit covering AppDataUpdate proposals, after the application
    /// has interpreted the proposals and computed the resulting
    /// [`AppDataUpdates`].
    ///
    /// The returned [`StagedCommit`] can be inspected and merged into the
    /// group's state using [`PublicGroup::merge_commit()`].
    #[cfg(feature = "extensions-draft")]
    pub fn stage_app_data_commit(
        &self,
        crypto: &impl OpenMlsCrypto,
        unresolved_commit: UnresolvedAppDataCommit,
        app_data_dict_updates: Option<AppDataUpdates>,
    ) -> Result<StagedCommit, StageCommitError> {
        self.stage_commit_with_app_data_updates(
            &unresolved_commit.into_content(),
            crypto,
            app_data_dict_updates,
        )
    }

    /// Resolves a [`ProcessedMessage`] carrying an
    /// [`ProcessedMessageContent::UnresolvedAppDataCommit`]: stages the commit
    /// with the application-computed [`AppDataUpdates`] and returns the same
    /// message with the resulting [`StagedCommit`] as regular
    /// [`ProcessedMessageContent::StagedCommitMessage`] content. All other
    /// message fields (sender, credential, authenticated data) are preserved.
    ///
    /// Use this instead of [`PublicGroup::stage_app_data_commit()`] when the
    /// caller needs the resolved commit in [`ProcessedMessage`] form, e.g. to
    /// keep a single code path for commits with and without AppDataUpdate
    /// proposals.
    ///
    /// Returns an error if the message content is not an unresolved app data
    /// commit; the message is consumed either way.
    #[cfg(feature = "extensions-draft")]
    pub fn resolve_app_data_commit(
        &self,
        crypto: &impl OpenMlsCrypto,
        processed_message: ProcessedMessage,
        app_data_dict_updates: Option<AppDataUpdates>,
    ) -> Result<ProcessedMessage, ResolveAppDataCommitError> {
        processed_message.map_content(|content| {
            let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved_commit) = content
            else {
                return Err(ResolveAppDataCommitError::NotAnUnresolvedAppDataCommit);
            };
            let staged_commit =
                self.stage_app_data_commit(crypto, *unresolved_commit, app_data_dict_updates)?;
            Ok(ProcessedMessageContent::StagedCommitMessage(Box::new(
                staged_commit,
            )))
        })
    }
}

impl PublicGroup {
    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    /// Checks the following semantic validation:
    ///  - ValSem008
    ///  - ValSem010
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
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
    ///    private keys from the direct path
    ///  - ValSem205
    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem244
    ///  - ValSem246 (as part of ValSem010)
    pub(crate) fn process_unverified_message(
        &self,
        crypto: &impl OpenMlsCrypto,
        unverified_message: UnverifiedMessage,
    ) -> Result<ProcessedMessage, PublicProcessMessageError> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        //  - https://validation.openmls.tech/#valn1203
        let verified = unverified_message.verify(self.ciphersuite(), crypto, self.version())?;
        let content = verified.content;
        let credential = verified.credential;

        #[cfg_attr(not(feature = "extensions-draft"), allow(unused_mut))]
        let mut processed = match content.sender() {
            Sender::Member(_) | Sender::NewMemberCommit | Sender::NewMemberProposal => {
                self.process_internal_authenticated_content(crypto, content, credential)?
            }
            Sender::External(_) => {
                self.process_external_authenticated_content(crypto, content, credential)?
            }
        };
        #[cfg(feature = "extensions-draft")]
        if self.group_context().safe_aad_required() {
            processed
                .try_attach_safe_aad()
                .map_err(|_| PublicProcessMessageError::MalformedSafeAad)?;
        }
        Ok(processed)
    }

    fn process_internal_authenticated_content(
        &self,
        crypto: &impl OpenMlsCrypto,
        content: AuthenticatedContent,
        credential: Credential,
    ) -> Result<ProcessedMessage, PublicProcessMessageError> {
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
                    crypto,
                    content,
                )?);
                if matches!(sender, Sender::NewMemberProposal) {
                    ProcessedMessageContent::ExternalJoinProposalMessage(proposal)
                } else {
                    ProcessedMessageContent::ProposalMessage(proposal)
                }
            }
            FramedContentBody::Commit(commit) => {
                // A commit covering AppDataUpdate proposals cannot be staged
                // immediately: the proposals contain diffs in an
                // application-defined format, so the application has to
                // interpret them and supply the resulting dictionary entries
                // first. The verified content is handed back to the caller,
                // who resumes staging via `PublicGroup::stage_app_data_commit`.
                #[cfg(feature = "extensions-draft")]
                {
                    let app_data_update_proposals =
                        committed_app_data_update_proposals(commit, &self.proposal_store);
                    if !app_data_update_proposals.is_empty() {
                        let unresolved_commit =
                            UnresolvedAppDataCommit::new(content, app_data_update_proposals);
                        return Ok(ProcessedMessage::new(
                            self.group_id().clone(),
                            self.group_context().epoch(),
                            sender,
                            authenticated_data,
                            ProcessedMessageContent::UnresolvedAppDataCommit(Box::new(
                                unresolved_commit,
                            )),
                            credential,
                            #[cfg(feature = "virtual-clients-draft")]
                            None,
                        ));
                    }
                }
                #[cfg(not(feature = "extensions-draft"))]
                let _ = commit;

                let staged_commit = self.stage_commit(&content, crypto)?;
                ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
            }
        };

        Ok(ProcessedMessage::new(
            self.group_id().clone(),
            self.group_context().epoch(),
            sender,
            authenticated_data,
            content,
            credential,
            #[cfg(feature = "virtual-clients-draft")]
            None,
        ))
    }

    fn process_external_authenticated_content(
        &self,
        crypto: &impl OpenMlsCrypto,
        content: AuthenticatedContent,
        credential: Credential,
    ) -> Result<ProcessedMessage, PublicProcessMessageError> {
        let sender = content.sender().clone();
        let data = content.authenticated_data().to_owned();

        debug_assert!(matches!(sender, Sender::External(_)));

        // https://validation.openmls.tech/#valn1501
        match content.content() {
            FramedContentBody::Application(_) => {
                Err(PublicProcessMessageError::UnauthorizedExternalApplicationMessage)
            }
            // TODO: https://validation.openmls.tech/#valn1502
            FramedContentBody::Proposal(Proposal::GroupContextExtensions(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        crypto,
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.group_context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                    #[cfg(feature = "virtual-clients-draft")]
                    None,
                ))
            }

            FramedContentBody::Proposal(Proposal::Remove(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        crypto,
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.group_context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                    #[cfg(feature = "virtual-clients-draft")]
                    None,
                ))
            }
            FramedContentBody::Proposal(Proposal::Add(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        crypto,
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.group_context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                    #[cfg(feature = "virtual-clients-draft")]
                    None,
                ))
            }
            // TODO #151/#106
            FramedContentBody::Proposal(_) => {
                Err(PublicProcessMessageError::UnsupportedProposalType)
            }
            FramedContentBody::Commit(_) => {
                Err(PublicProcessMessageError::UnauthorizedExternalCommitMessage)
            }
        }
    }
}
