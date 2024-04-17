use core_group::proposals::QueuedProposal;
use openmls_traits::storage::StorageProvider;

use crate::{
    framing::mls_content::FramedContentBody,
    group::{
        errors::{MergeCommitError, StageCommitError, ValidationError},
        mls_group::errors::ProcessMessageError,
    },
};

use super::{proposals::ProposalStore, *};

impl CoreGroup {
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
    ///               members of the group
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
    ///  - ValSem244
    ///  - ValSem246 (as part of ValSem010)
    pub(crate) fn process_unverified_message(
        &self,
        provider: &impl OpenMlsProvider,
        unverified_message: UnverifiedMessage,
        proposal_store: &ProposalStore,
        old_epoch_keypairs: Vec<EncryptionKeyPair>,
        leaf_node_keypairs: Vec<EncryptionKeyPair>,
    ) -> Result<ProcessedMessage, ProcessMessageError> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        let (content, credential) =
            unverified_message.verify(self.ciphersuite(), provider.crypto(), self.version())?;

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
                            old_epoch_keypairs,
                            leaf_node_keypairs,
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

    /// This function is used to parse messages from the DS. It checks for
    /// syntactic errors and does semantic validation as well. If the input is a
    /// [PrivateMessage] message, it will be decrypted. It returns a
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
    ///  - ValSem113: All Proposals: The proposal type must be supported by all
    ///               members of the group
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
    ///  - ValSem244
    ///  - ValSem245
    ///  - ValSem246 (as part of ValSem010)
    pub(crate) fn process_message(
        &mut self,
        provider: &impl OpenMlsProvider,
        message: impl Into<ProtocolMessage>,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
        proposal_store: &ProposalStore,
        own_leaf_nodes: &[LeafNode],
    ) -> Result<ProcessedMessage, ProcessMessageError> {
        let message: ProtocolMessage = message.into();

        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        //  - ValSem006
        //  - ValSem007 MembershipTag presence
        let decrypted_message =
            self.decrypt_message(provider.crypto(), message, sender_ratchet_configuration)?;

        let unverified_message = self
            .public_group
            .parse_message(decrypted_message, &self.message_secrets_store)
            .map_err(ProcessMessageError::from)?;

        // If this is a commit, we need to load the private key material we need for decryption.
        let (old_epoch_keypairs, leaf_node_keypairs) =
            if let ContentType::Commit = unverified_message.content_type() {
                self.read_decryption_keypairs(provider, own_leaf_nodes)?
            } else {
                (vec![], vec![])
            };

        self.process_unverified_message(
            provider,
            unverified_message,
            proposal_store,
            old_epoch_keypairs,
            leaf_node_keypairs,
        )
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
                    public_message,
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

    /// Helper function to read decryption keypairs.
    pub(super) fn read_decryption_keypairs(
        &self,
        provider: &impl OpenMlsProvider,
        own_leaf_nodes: &[LeafNode],
    ) -> Result<(Vec<EncryptionKeyPair>, Vec<EncryptionKeyPair>), StageCommitError> {
        // All keys from the previous epoch are potential decryption keypairs.
        let old_epoch_keypairs = self.read_epoch_keypairs(provider.key_store());

        // If we are processing an update proposal that originally came from
        // us, the keypair corresponding to the leaf in the update is also a
        // potential decryption keypair.
        let leaf_node_keypairs = own_leaf_nodes
            .iter()
            .map(|leaf_node| {
                EncryptionKeyPair::read_from_key_store(provider, leaf_node.encryption_key())
                    .ok_or(StageCommitError::MissingDecryptionKey)
            })
            .collect::<Result<Vec<EncryptionKeyPair>, StageCommitError>>()?;

        Ok((old_epoch_keypairs, leaf_node_keypairs))
    }

    /// Merge a [StagedCommit] into the group after inspection
    pub(crate) fn merge_staged_commit<KeyStore: OpenMlsKeyStore, Storage: StorageProvider<1>>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore, StorageProvider = Storage>,
        staged_commit: StagedCommit,
        proposal_store: &mut ProposalStore,
    ) -> Result<(), MergeCommitError<KeyStore::Error, Storage::UpdateError>> {
        // Save the past epoch
        let past_epoch = self.context().epoch();
        // Get all the full leaves
        let leaves = self.public_group().members().collect();
        // Merge the staged commit into the group state and store the secret tree from the
        // previous epoch in the message secrets store.
        if let Some(message_secrets) = self.merge_commit(provider, staged_commit)? {
            self.message_secrets_store
                .add(past_epoch, message_secrets, leaves);
        }
        // Empty the proposal store
        proposal_store.empty();
        Ok(())
    }
}
