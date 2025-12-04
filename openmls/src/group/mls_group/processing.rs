//! Processing functions of an [`MlsGroup`] for incoming messages.

use std::mem;

use errors::{CommitToPendingProposalsError, MergePendingCommitError};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, storage::StorageProvider as _};

use crate::{
    framing::mls_content::FramedContentBody,
    group::{errors::MergeCommitError, StageCommitError, ValidationError},
    messages::group_info::GroupInfo,
    storage::OpenMlsProvider,
    tree::sender_ratchet::SenderRatchetConfiguration,
};

#[cfg(feature = "extensions-draft-08")]
use crate::{
    component::{ComponentData, ComponentId},
    extensions::AppDataDictionary,
};

#[cfg(feature = "extensions-draft-08")]
use std::collections::BTreeMap;

use super::{errors::ProcessMessageError, *};

#[cfg(feature = "extensions-draft-08")]
/// keeps the old dictionary as well as the values that are being overwritten
pub struct AppDataDictionaryUpdater<'a> {
    old_dict: Option<&'a AppDataDictionary>,
    new_entries: Option<AppDataUpdates>,
}

/// A diff of update values that can be provided to [`MlsGroup::process_unverified_message()`]
/// or [`CommitBuilder::with_app_data_dictionary_updates()`]
#[cfg(feature = "extensions-draft-08")]
#[derive(Default, Debug)]
pub struct AppDataUpdates(BTreeMap<ComponentId, Option<Vec<u8>>>);

#[cfg(feature = "extensions-draft-08")]
impl AppDataUpdates {
    pub fn into_iter(self) -> impl Iterator<Item = (ComponentId, Option<Vec<u8>>)> {
        self.0.into_iter()
    }
    pub fn len(&self) -> usize {
        self.0.iter().count()
    }
}

#[cfg(feature = "extensions-draft-08")]
impl<'a> AppDataDictionaryUpdater<'a> {
    pub fn new(old_dict: Option<&'a AppDataDictionary>) -> Self {
        Self {
            old_dict,
            new_entries: None,
        }
    }

    /// helper method that returns a mutable reference to the
    /// [`AppDataUpdates`], creating the struct if it does not exist.
    fn new_entries_mut(&mut self) -> &mut AppDataUpdates {
        self.new_entries
            .get_or_insert_with(|| AppDataUpdates(BTreeMap::new()))
    }

    /// sets a value in the new_entries. if we already have data for that component id, overwrite
    /// it. else add it in the right position.
    pub fn set(&mut self, component_data: ComponentData) {
        let (id, data) = component_data.into_parts();

        self.new_entries_mut().0.insert(id, Some(data.into()));
    }

    pub fn remove(&mut self, id: &ComponentId) {
        self.new_entries_mut().0.insert(*id, None);
    }

    /// consumes the updater and returns just the changes, so we can pass them into
    /// process_unverified_message
    /// only returns Some if we actually called set
    pub fn changes(self) -> Option<AppDataUpdates> {
        self.new_entries
    }
}

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
        let unverified_message = self.unprotect_message(provider, message)?;

        self.process_unverified_message(
            provider,
            unverified_message,
            #[cfg(feature = "extensions-draft-08")]
            None,
        )
    }

    #[cfg(feature = "extensions-draft-08")]
    /// returns a new helper struct for updating the app data
    pub fn app_data_dictionary_updater<'a>(&'a self) -> AppDataDictionaryUpdater<'a> {
        AppDataDictionaryUpdater::new(self.context().app_data_dict())
    }

    /// Parses and deprotects incoming messages from the DS. Checks for syntactic errors, but only
    /// performs limited semantic checks.
    pub fn unprotect_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<UnverifiedMessage, ProcessMessageError<Provider::StorageError>> {
        // Make sure we are still a member of the group
        if !self.is_active() {
            return Err(ProcessMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        let message = message.into();

        // Check that handshake messages are compatible with the incoming wire format policy
        if !message.is_external()
            && message.is_handshake_message()
            && !self
                .configuration()
                .wire_format_policy()
                .incoming()
                .is_compatible_with(message.wire_format())
        {
            return Err(ProcessMessageError::IncompatibleWireFormat);
        }

        // Parse the message
        let sender_ratchet_configuration = *self.configuration().sender_ratchet_configuration();

        // Check if this message will modify the secret tree when decrypting a
        // private message
        let will_modify_secret_tree = matches!(message, ProtocolMessage::PrivateMessage(_));

        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        //  - ValSem006
        //  - ValSem007 MembershipTag presence
        let decrypted_message =
            self.decrypt_message(provider.crypto(), message, &sender_ratchet_configuration)?;

        // Persist the secret tree if it was modified to ensure forward secrecy
        if will_modify_secret_tree {
            provider
                .storage()
                .write_message_secrets(self.group_id(), &self.message_secrets_store)
                .map_err(ProcessMessageError::StorageError)?;
        }

        let unverified_message = self
            .public_group
            .parse_message(decrypted_message, &self.message_secrets_store)
            .map_err(ProcessMessageError::from)?;

        Ok(unverified_message)
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        proposal: QueuedProposal,
    ) -> Result<(), Storage::Error> {
        storage.queue_proposal(self.group_id(), &proposal.proposal_reference(), &proposal)?;
        // Store the proposal in in the internal ProposalStore
        self.proposal_store_mut().add(proposal);

        Ok(())
    }

    /// Returns true if there are pending proposals queued in the proposal store.
    pub fn has_pending_proposals(&self) -> bool {
        !self.proposal_store().is_empty()
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

        // Build and stage the commit using the commit builder
        // TODO #751
        let (commit, welcome, group_info) = self
            .commit_builder()
            // This forces committing to the proposals in the proposal store:
            .consume_proposal_store(true)
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .stage_commit(provider)?
            .into_contents();

        Ok((
            commit,
            // Turn the [`Welcome`] to an [`MlsMessageOut`], if there is one
            welcome.map(|welcome| MlsMessageOut::from_welcome(welcome, self.version())),
            group_info,
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
        self.merge_commit(provider, staged_commit)?;

        // Extract and store the resumption psk for the current epoch
        let resumption_psk = self.group_epoch_secrets().resumption_psk();
        self.resumption_psk_store
            .add(self.context().epoch(), resumption_psk.clone());
        provider
            .storage()
            .write_resumption_psk_store(self.group_id(), &self.resumption_psk_store)
            .map_err(MergeCommitError::StorageError)?;

        // Delete own KeyPackageBundles
        self.own_leaf_nodes.clear();
        provider
            .storage()
            .delete_own_leaf_nodes(self.group_id())
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

    /// Helper function to read decryption keypairs.
    pub(super) fn read_decryption_keypairs(
        &self,
        provider: &impl OpenMlsProvider,
        own_leaf_nodes: &[LeafNode],
    ) -> Result<(Vec<EncryptionKeyPair>, Vec<EncryptionKeyPair>), StageCommitError> {
        // All keys from the previous epoch are potential decryption keypairs.
        let old_epoch_keypairs = self.read_epoch_keypairs(provider.storage()).map_err(|e| {
            log::error!("Error reading epoch keypairs: {e:?}");
            StageCommitError::MissingDecryptionKey
        })?;

        // If we are processing an update proposal that originally came from
        // us, the keypair corresponding to the leaf in the update is also a
        // potential decryption keypair.
        let leaf_node_keypairs = own_leaf_nodes
            .iter()
            .map(|leaf_node| {
                EncryptionKeyPair::read(provider, leaf_node.encryption_key())
                    .ok_or(StageCommitError::MissingDecryptionKey)
            })
            .collect::<Result<Vec<EncryptionKeyPair>, StageCommitError>>()?;

        Ok((old_epoch_keypairs, leaf_node_keypairs))
    }

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
    ///  - ValSem113: All Proposals: The proposal type must be supported by all
    ///    members of the group
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
    pub fn process_unverified_message<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        unverified_message: UnverifiedMessage,
        #[cfg(feature = "extensions-draft-08")] app_data_dict_updates: Option<AppDataUpdates>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        //  - https://validation.openmls.tech/#valn1302
        //  - https://validation.openmls.tech/#valn1304
        let (content, credential) =
            unverified_message.verify(self.ciphersuite(), provider.crypto(), self.version())?;

        match content.sender() {
            Sender::Member(_) | Sender::NewMemberCommit | Sender::NewMemberProposal => {
                let sender = content.sender().clone();
                let authenticated_data = content.authenticated_data().to_owned();
                let epoch = content.epoch();

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
                        // DELETE BEFORE MERGE: This was moved here from process_message2
                        // Since this is a commit, we need to load the private key material we need for decryption.
                        let (old_epoch_keypairs, leaf_node_keypairs) =
                            self.read_decryption_keypairs(provider, &self.own_leaf_nodes)?;

                        let staged_commit = self.stage_commit(
                            &content,
                            old_epoch_keypairs,
                            leaf_node_keypairs,
                            #[cfg(feature = "extensions-draft-08")]
                            app_data_dict_updates,
                            provider,
                        )?;

                        ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
                    }
                };

                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    epoch,
                    sender,
                    authenticated_data,
                    content,
                    credential,
                ))
            }
            Sender::External(_) => {
                let sender = content.sender().clone();
                let data = content.authenticated_data().to_owned();
                // https://validation.openmls.tech/#valn1501
                match content.content() {
                    FramedContentBody::Application(_) => {
                        Err(ProcessMessageError::UnauthorizedExternalApplicationMessage)
                    }
                    // TODO: https://validation.openmls.tech/#valn1502
                    FramedContentBody::Proposal(Proposal::GroupContextExtensions(_)) => {
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
                    FramedContentBody::Proposal(Proposal::Add(_)) => {
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
                    FramedContentBody::Commit(_) => {
                        Err(ProcessMessageError::UnauthorizedExternalCommitMessage)
                    }
                }
            }
        }
    }

    /// Performs framing validation and, if necessary, decrypts the given message.
    ///
    /// Returns the [`DecryptedMessage`] if processing is successful, or a
    /// [`ValidationError`] if it is not.
    ///
    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    ///  - ValSem006
    ///  - ValSem007 MembershipTag presence
    ///  - https://validation.openmls.tech/#valn1202
    pub(crate) fn decrypt_message(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        message: ProtocolMessage,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
    ) -> Result<DecryptedMessage, ValidationError> {
        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        self.public_group.validate_framing(&message)?;

        let epoch = message.epoch();

        // Checks the following semantic validation:
        //  - ValSem006
        //  - ValSem007 MembershipTag presence
        match message {
            ProtocolMessage::PublicMessage(public_message) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first.
                let message_secrets =
                    self.message_secrets_for_epoch(epoch).map_err(|e| match e {
                        SecretTreeError::TooDistantInThePast => ValidationError::NoPastEpochData,
                        _ => LibraryError::custom(
                            "Unexpected error while retrieving message secrets for epoch.",
                        )
                        .into(),
                    })?;
                DecryptedMessage::from_inbound_public_message(
                    *public_message,
                    message_secrets,
                    message_secrets.serialized_context().to_vec(),
                    crypto,
                    self.ciphersuite(),
                )
            }
            ProtocolMessage::PrivateMessage(ciphertext) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first
                DecryptedMessage::from_inbound_ciphertext(
                    ciphertext,
                    crypto,
                    self,
                    sender_ratchet_configuration,
                )
            }
        }
    }
}
