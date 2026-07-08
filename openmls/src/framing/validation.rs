//! # Validation steps for incoming messages
//!
//! ```text
//!
//!                             MlsMessageIn
//!                                  │                    -.
//!                                  │                      │
//!                                  │                      │
//!                                  ▼                      │
//!                           DecryptedMessage              +-- parse_message
//!                                  │                      │
//!                                  │                      │
//!                                  │                      │
//!                                  ▼                    -'
//!                           UnverifiedMessage
//!                                  │                    -.
//!                                  │                      │
//!                                  │                      +-- process_unverified_message
//!                                  │                      │
//!                                  ▼                    -'
//!                          ProcessedMessage
//!
//! ```

use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use proposal_store::QueuedProposal;

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::signable::Verifiable,
    error::LibraryError,
    extensions::ExternalSendersExtension,
    group::{errors::ValidationError, mls_group::staged_commit::StagedCommit},
    tree::sender_ratchet::SenderRatchetConfiguration,
    versions::ProtocolVersion,
};

#[cfg(feature = "extensions-draft")]
use crate::{
    component::ComponentId,
    framing::safe_aad::SafeAad,
    group::{
        errors::StageCommitError,
        mls_group::{errors::ResolveAppDataCommitError, processing::UnresolvedAppDataCommit},
    },
};

use super::{
    mls_auth_content::AuthenticatedContent,
    mls_auth_content_in::{AuthenticatedContentIn, VerifiableAuthenticatedContentIn},
    private_message_in::PrivateMessageIn,
    public_message_in::PublicMessageIn,
    *,
};

/// Result of decrypting an inbound PrivateMessage: either content this client
/// can process further, or a message this client authored itself, which it
/// cannot decrypt.
#[derive(Debug)]
pub(crate) enum InboundDecryptionResult {
    /// A message from another sender or from a sibling emulator client (with
    /// the `virtual-clients-draft` feature), decrypted and ready for parsing.
    Decrypted(DecryptedMessage),
    /// A private message whose sender data claims this client's own leaf.
    /// Carries the plaintext framing fields needed to build the
    /// [`ProcessedMessage`], since the content itself cannot be decrypted.
    OwnPrivateMessage {
        epoch: GroupEpoch,
        authenticated_data: Vec<u8>,
    },
}

impl InboundDecryptionResult {
    /// Returns the decrypted message, or `None` for an own private message.
    #[cfg(test)]
    pub(crate) fn into_decrypted(self) -> Option<DecryptedMessage> {
        match self {
            Self::Decrypted(message) => Some(message),
            Self::OwnPrivateMessage { .. } => None,
        }
    }
}

/// Intermediate message that can be constructed either from a public message or from private message.
/// If it it constructed from a ciphertext message, the ciphertext message is decrypted first.
/// This function implements the following checks:
///  - ValSem005
///  - ValSem007
///  - ValSem009
#[derive(Debug)]
pub(crate) struct DecryptedMessage {
    verifiable_content: VerifiableAuthenticatedContentIn,
    /// Recovered sender emulation-group leaf index for an application
    /// message from a sibling emulator client.
    #[cfg(feature = "virtual-clients-draft")]
    emulator_sender_leaf_index: Option<LeafNodeIndex>,
}

impl DecryptedMessage {
    /// Constructs a [DecryptedMessage] from a [VerifiableAuthenticatedContent].
    pub(crate) fn from_inbound_public_message<'a>(
        public_message: PublicMessageIn,
        message_secrets_option: impl Into<Option<&'a MessageSecrets>>,
        serialized_context: Vec<u8>,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<Self, ValidationError> {
        if public_message.sender().is_member() {
            // ValSem007 Membership tag presence
            if public_message.membership_tag().is_none() {
                return Err(ValidationError::MissingMembershipTag);
            }

            if let Some(message_secrets) = message_secrets_option.into() {
                // Verify the membership tag. This needs to be done explicitly for PublicMessage messages,
                // it is implicit for PrivateMessage messages (because the encryption can only be known by members).
                // ValSem008
                // https://validation.openmls.tech/#valn1302
                public_message.verify_membership(
                    crypto,
                    ciphersuite,
                    message_secrets.membership_key(),
                    message_secrets.serialized_context(),
                )?;
            }
        }

        let verifiable_content = public_message.into_verifiable_content(serialized_context);

        // Public messages don't carry a reuse_guard, so no emulator
        // sender leaf index to recover.
        Self::from_verifiable_content(
            verifiable_content,
            #[cfg(feature = "virtual-clients-draft")]
            None,
        )
    }

    /// Constructs a [DecryptedMessage] from a [PrivateMessage] by attempting to decrypt it
    /// to a [VerifiableAuthenticatedContent] first.
    pub(crate) fn from_inbound_ciphertext(
        ciphertext: PrivateMessageIn,
        crypto: &impl OpenMlsCrypto,
        group: &mut MlsGroup,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
        #[cfg(feature = "virtual-clients-draft")] emulator_ctx: Option<
            &crate::framing::private_message::EmulatorReuseGuardCtx<'_>,
        >,
    ) -> Result<InboundDecryptionResult, ValidationError> {
        // This will be refactored with #265.
        let ciphersuite = group.ciphersuite();
        // TODO: #819 The old leaves should not be needed any more.
        //       Revisit when the transition is further along.
        let (message_secrets, _old_leaves) = group
            .message_secrets_and_leaves(ciphertext.epoch())
            .map_err(MessageDecryptionError::SecretTreeError)?;
        let sender_data = ciphertext.sender_data(message_secrets, crypto, ciphersuite)?;
        let own_sender = sender_data.leaf_index == group.own_leaf_index();
        // If we are the sender, the content cannot be decrypted and the
        // signature cannot be verified: the own sender ratchet only produces
        // encryption keys. Return early before touching any ratchet state so
        // no decryption counter is consumed. With the `virtual-clients-draft`
        // feature, own-leaf messages are decryptable instead (sibling
        // emulator clients share the leaf, and the dual-use ratchet retains
        // the secrets of unconfirmed own sends), so decryption is attempted
        // below and only its failure surfaces the message as an own private
        // message.
        #[cfg(not(feature = "virtual-clients-draft"))]
        if own_sender {
            return Ok(InboundDecryptionResult::OwnPrivateMessage {
                epoch: ciphertext.epoch(),
                authenticated_data: ciphertext.aad().to_vec(),
            });
        }
        #[cfg(feature = "virtual-clients-draft")]
        let effective_emulator_ctx = match emulator_ctx {
            Some(ctx) if own_sender => Some(ctx),
            _ => None,
        };
        let message_secrets = group
            .message_secrets_for_epoch_mut(ciphertext.epoch())
            .map_err(|_| MessageDecryptionError::AeadError)?;
        let decrypt_result = ciphertext.to_verifiable_content(
            ciphersuite,
            crypto,
            message_secrets,
            sender_data.leaf_index,
            sender_ratchet_configuration,
            sender_data,
            #[cfg(feature = "virtual-clients-draft")]
            effective_emulator_ctx,
        );
        #[cfg(not(feature = "virtual-clients-draft"))]
        let decrypted = decrypt_result?;
        #[cfg(feature = "virtual-clients-draft")]
        let decrypted = match decrypt_result {
            Ok(decrypted) => decrypted,
            // In a group that does not use virtual clients (no emulator
            // context resolved for the epoch), an own message that fails to
            // decrypt is an echo of a send this client already confirmed or
            // processed. In groups that do use virtual clients, failures
            // keep surfacing as errors, since the message may come from a
            // sibling emulator client.
            Err(_) if own_sender && emulator_ctx.is_none() => {
                return Ok(InboundDecryptionResult::OwnPrivateMessage {
                    epoch: ciphertext.epoch(),
                    authenticated_data: ciphertext.aad().to_vec(),
                });
            }
            Err(e) => return Err(e.into()),
        };
        Self::from_verifiable_content(
            decrypted.verifiable,
            #[cfg(feature = "virtual-clients-draft")]
            decrypted.emulator_sender_leaf_index,
        )
        .map(InboundDecryptionResult::Decrypted)
    }

    // Internal constructor function. Does the following checks:
    // - Confirmation tag must be present for Commit messages
    // - Membership tag must be present for member messages, if the original incoming message was not an PrivateMessage
    // - Ensures application messages were originally PrivateMessage messages
    fn from_verifiable_content(
        verifiable_content: VerifiableAuthenticatedContentIn,
        #[cfg(feature = "virtual-clients-draft")] emulator_sender_leaf_index: Option<LeafNodeIndex>,
    ) -> Result<Self, ValidationError> {
        // ValSem009
        if verifiable_content.content_type() == ContentType::Commit
            && verifiable_content.confirmation_tag().is_none()
        {
            return Err(ValidationError::MissingConfirmationTag);
        }
        // ValSem005
        if verifiable_content.content_type() == ContentType::Application {
            if verifiable_content.wire_format() != WireFormat::PrivateMessage {
                return Err(ValidationError::UnencryptedApplicationMessage);
            } else if !verifiable_content.sender().is_member() {
                // This should not happen because the sender of an PrivateMessage should always be a member
                return Err(LibraryError::custom("Expected sender to be member.").into());
            }
        }
        Ok(DecryptedMessage {
            verifiable_content,
            #[cfg(feature = "virtual-clients-draft")]
            emulator_sender_leaf_index,
        })
    }

    /// Recovered sender emulation-group leaf index, if the message came
    /// from a sibling emulator client.
    #[cfg(feature = "virtual-clients-draft")]
    #[allow(dead_code)]
    pub(crate) fn emulator_sender_leaf_index(&self) -> Option<LeafNodeIndex> {
        self.emulator_sender_leaf_index
    }

    /// Gets the correct credential from the message depending on the sender type.
    ///
    /// The closure argument is used to look up the credential and signature key. If the epoch of
    /// the message is the same as that of the group, look it up in the tree; else, look in up in
    /// the past trees of the message secret store.
    ///
    /// Checks the following semantic validation:
    ///  - ValSem112
    ///  - ValSem245
    ///  - Prepares ValSem246 by setting the right credential. The remainder
    ///    of ValSem246 is validated as part of ValSem010.
    ///  - [valn1301](https://validation.openmls.tech/#valn1301)
    ///
    /// Returns the [`Credential`] and the leaf's [`SignaturePublicKey`].
    pub(crate) fn credential(
        &self,
        look_up_credential_with_key: impl Fn(LeafNodeIndex) -> Option<CredentialWithKey>,
        external_senders: Option<&ExternalSendersExtension>,
    ) -> Result<CredentialWithKey, ValidationError> {
        let sender = self.sender();
        match sender {
            Sender::Member(leaf_index) => {
                // https://validation.openmls.tech/#valn1306
                look_up_credential_with_key(*leaf_index).ok_or(ValidationError::UnknownMember)
            }
            Sender::External(index) => {
                let sender = external_senders
                    .ok_or(ValidationError::NoExternalSendersExtension)?
                    .get(index.index())
                    .ok_or(ValidationError::UnauthorizedExternalSender)?;
                Ok(CredentialWithKey {
                    credential: sender.credential().clone(),
                    signature_key: sender.signature_key().clone(),
                })
            }
            Sender::NewMemberCommit | Sender::NewMemberProposal => {
                // Fetch the credential from the message itself.
                // https://validation.openmls.tech/#valn0407
                self.verifiable_content.new_member_credential()
            }
        }
    }

    /// Returns the sender.
    pub fn sender(&self) -> &Sender {
        self.verifiable_content.sender()
    }

    /// Returns the [`VerifiableAuthenticatedContent`].
    pub(crate) fn verifiable_content(&self) -> &VerifiableAuthenticatedContentIn {
        &self.verifiable_content
    }
}

/// Result of [`UnverifiedMessage::verify`].
pub(crate) struct VerifiedMessage {
    pub(crate) content: AuthenticatedContent,
    pub(crate) credential: Credential,
    #[cfg(feature = "virtual-clients-draft")]
    pub(crate) emulator_sender_leaf_index: Option<LeafNodeIndex>,
}

/// Context that is needed to verify the signature of a the leaf node of an
/// UpdatePath or an update proposal.
#[derive(Debug, Clone)]
pub(crate) enum SenderContext {
    Member((GroupId, LeafNodeIndex)),
    ExternalCommit {
        group_id: GroupId,
        leftmost_blank_index: LeafNodeIndex,
        self_removes_in_store: Vec<SelfRemoveInStore>,
    },
}

/// Partially checked and potentially decrypted message (if it was originally encrypted).
/// Use this to inspect the [`Credential`] of the message sender
/// and the optional `aad` if the original message was encrypted.
/// The [`OpenMlsSignaturePublicKey`] is used to verify the signature of the
/// message.
#[derive(Debug, Clone)]
pub struct UnverifiedMessage {
    verifiable_content: VerifiableAuthenticatedContentIn,
    credential: Credential,
    sender_pk: OpenMlsSignaturePublicKey,
    sender_context: Option<SenderContext>,
    /// See [`DecryptedMessage::emulator_sender_leaf_index`].
    #[cfg(feature = "virtual-clients-draft")]
    emulator_sender_leaf_index: Option<LeafNodeIndex>,
}

impl UnverifiedMessage {
    /// Construct an [UnverifiedMessage] from a [DecryptedMessage] and an optional [Credential].
    pub(crate) fn from_decrypted_message(
        decrypted_message: DecryptedMessage,
        credential: Credential,
        sender_pk: OpenMlsSignaturePublicKey,
        sender_context: Option<SenderContext>,
    ) -> Self {
        #[cfg(feature = "virtual-clients-draft")]
        let emulator_sender_leaf_index = decrypted_message.emulator_sender_leaf_index;
        UnverifiedMessage {
            verifiable_content: decrypted_message.verifiable_content,
            credential,
            sender_pk,
            sender_context,
            #[cfg(feature = "virtual-clients-draft")]
            emulator_sender_leaf_index,
        }
    }

    /// Verify the [`UnverifiedMessage`].
    pub(crate) fn verify(
        self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        protocol_version: ProtocolVersion,
    ) -> Result<VerifiedMessage, ValidationError> {
        let content: AuthenticatedContentIn = self
            .verifiable_content
            .verify(crypto, &self.sender_pk)
            .map_err(|_| ValidationError::InvalidSignature)?;
        // https://validation.openmls.tech/#valn1302
        // https://validation.openmls.tech/#valn1304
        let content =
            content.validate(ciphersuite, crypto, self.sender_context, protocol_version)?;
        Ok(VerifiedMessage {
            content,
            credential: self.credential,
            #[cfg(feature = "virtual-clients-draft")]
            emulator_sender_leaf_index: self.emulator_sender_leaf_index,
        })
    }
}

/// A message that has passed all syntax and semantics checks.
#[derive(Debug)]
pub struct ProcessedMessage {
    group_id: GroupId,
    epoch: GroupEpoch,
    sender: Sender,
    authenticated_data: Vec<u8>,
    content: ProcessedMessageContent,
    credential: Credential,
    /// See [`Self::emulator_sender_leaf_index`].
    #[cfg(feature = "virtual-clients-draft")]
    emulator_sender_leaf_index: Option<LeafNodeIndex>,
    /// Parsed Safe AAD prefix, populated only when the message's GroupContext
    /// required Safe AAD framing. `None` otherwise.
    #[cfg(feature = "extensions-draft")]
    safe_aad: Option<SafeAad>,
    /// Length in bytes of the Safe AAD prefix at the start of
    /// `authenticated_data`. Zero when [`Self::safe_aad`] is `None`.
    #[cfg(feature = "extensions-draft")]
    safe_aad_prefix_len: usize,
}

impl ProcessedMessage {
    /// Create a new `ProcessedMessage`.
    pub(crate) fn new(
        group_id: GroupId,
        epoch: GroupEpoch,
        sender: Sender,
        authenticated_data: Vec<u8>,
        content: ProcessedMessageContent,
        credential: Credential,
        #[cfg(feature = "virtual-clients-draft")] emulator_sender_leaf_index: Option<LeafNodeIndex>,
    ) -> Self {
        Self {
            group_id,
            epoch,
            sender,
            authenticated_data,
            content,
            credential,
            #[cfg(feature = "virtual-clients-draft")]
            emulator_sender_leaf_index,
            #[cfg(feature = "extensions-draft")]
            safe_aad: None,
            #[cfg(feature = "extensions-draft")]
            safe_aad_prefix_len: 0,
        }
    }

    /// Swaps an [`ProcessedMessageContent::UnresolvedAppDataCommit`] for the
    /// [`StagedCommit`] produced by `stage`, keeping all other fields (sender,
    /// credential, authenticated data, Safe AAD state) intact.
    ///
    /// Returns an error if the content is not an unresolved app data commit;
    /// the message is consumed either way.
    #[cfg(feature = "extensions-draft")]
    pub(crate) fn resolve_app_data_commit(
        mut self,
        stage: impl FnOnce(UnresolvedAppDataCommit) -> Result<StagedCommit, StageCommitError>,
    ) -> Result<Self, ResolveAppDataCommitError> {
        let ProcessedMessageContent::UnresolvedAppDataCommit(unresolved_commit) = self.content
        else {
            return Err(ResolveAppDataCommitError::NotAnUnresolvedAppDataCommit);
        };
        let staged_commit = stage(*unresolved_commit)?;
        self.content = ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit));
        Ok(self)
    }

    /// Parse the Safe AAD prefix at the start of `authenticated_data` and
    /// attach it to this message. Callers should invoke this only when the receiving
    /// group's GroupContext requires Safe AAD framing. Otherwise, `safe_aad`
    /// stays `None` and `authenticated_data` is the caller-supplied bytes
    /// untouched.
    #[cfg(feature = "extensions-draft")]
    pub(crate) fn try_attach_safe_aad(&mut self) -> Result<(), crate::framing::SafeAadError> {
        let (safe_aad, prefix_len) =
            crate::framing::safe_aad::parse_authenticated_data_prefix(&self.authenticated_data)?;
        self.safe_aad = Some(safe_aad);
        self.safe_aad_prefix_len = prefix_len;
        Ok(())
    }

    /// Returns the parsed Safe AAD struct, or `None` if Safe AAD was not
    /// active for the group this message belongs to.
    #[cfg(feature = "extensions-draft")]
    pub fn safe_aad(&self) -> Option<&SafeAad> {
        self.safe_aad.as_ref()
    }

    /// Look up a Safe AAD item by [`ComponentId`].
    #[cfg(feature = "extensions-draft")]
    pub fn safe_aad_item(&self, component_id: crate::component::ComponentId) -> Option<&[u8]> {
        self.safe_aad
            .as_ref()
            .and_then(|safe_aad| safe_aad.get(component_id))
    }

    /// Returns the bytes of `authenticated_data` after any Safe AAD prefix.
    /// Equal to [`Self::aad`] when no Safe AAD prefix is present.
    #[cfg(feature = "extensions-draft")]
    pub fn tail_aad(&self) -> &[u8] {
        &self.authenticated_data[self.safe_aad_prefix_len..]
    }

    /// Returns the sender's leaf index in the emulation group when this
    /// message is an application message from a sibling emulator client.
    #[cfg(feature = "virtual-clients-draft")]
    pub fn emulator_sender_leaf_index(&self) -> Option<LeafNodeIndex> {
        self.emulator_sender_leaf_index
    }

    /// Returns the group ID of the message.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Returns the epoch of the message.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }

    /// Returns the sender of the message.
    pub fn sender(&self) -> &Sender {
        &self.sender
    }

    /// Returns the additional authenticated data (AAD) of the message.
    pub fn aad(&self) -> &[u8] {
        &self.authenticated_data
    }

    /// Returns the content of the message.
    pub fn content(&self) -> &ProcessedMessageContent {
        &self.content
    }

    /// Returns the content of the message and consumes the message.
    pub fn into_content(self) -> ProcessedMessageContent {
        self.content
    }

    /// Returns the credential of the message.
    pub fn credential(&self) -> &Credential {
        &self.credential
    }

    /// Safely export a value if the content of the processed message is a
    /// [`StagedCommit`].
    #[cfg(feature = "extensions-draft")]
    pub fn safe_export_secret<Crypto: OpenMlsCrypto>(
        &mut self,
        crypto: &Crypto,
        component_id: ComponentId,
    ) -> Result<Vec<u8>, ProcessedMessageSafeExportSecretError> {
        if let ProcessedMessageContent::StagedCommitMessage(ref mut staged_commit) =
            &mut self.content
        {
            let secret = staged_commit.safe_export_secret(crypto, component_id)?;
            Ok(secret)
        } else {
            Err(ProcessedMessageSafeExportSecretError::NotACommit)
        }
    }
}

/// Content of a processed message.
///
/// See the content variants' documentation for more information.
/// [`StagedCommit`] and [`QueuedProposal`] can be inspected for authorization purposes.
#[derive(Debug)]
pub enum ProcessedMessageContent {
    /// An application message.
    ///
    /// The [`ApplicationMessage`] contains a vector of bytes that can be used right-away.
    ApplicationMessage(ApplicationMessage),
    /// A standalone proposal.
    ///
    /// The [`QueuedProposal`] can be inspected for authorization purposes by the application.
    /// If the proposal is deemed to be allowed, it should be added to the group's proposal
    /// queue using [`MlsGroup::store_pending_proposal()`](crate::group::mls_group::MlsGroup::store_pending_proposal()).
    ProposalMessage(Box<QueuedProposal>),
    /// An [external join proposal](crate::prelude::JoinProposal) sent by a
    /// [NewMemberProposal](crate::prelude::Sender::NewMemberProposal) sender which is outside the group.
    ///
    /// Since this originates from a party outside the group, the [`QueuedProposal`] SHOULD be
    /// inspected for authorization purposes by the application. If the proposal is deemed to be
    /// allowed, it should be added to the group's proposal queue using
    /// [`MlsGroup::store_pending_proposal()`](crate::group::mls_group::MlsGroup::store_pending_proposal()).
    ExternalJoinProposalMessage(Box<QueuedProposal>),
    /// A Commit message.
    ///
    /// The [`StagedCommit`] can be inspected for authorization purposes by the application.
    /// If the type of the commit and the proposals it covers are deemed to be allowed,
    /// the commit should be merged into the group's state using
    /// [`MlsGroup::merge_staged_commit()`](crate::group::mls_group::MlsGroup::merge_staged_commit()).
    StagedCommitMessage(Box<StagedCommit>),
    /// A Commit authored by this client that it got fanned out by the delivery
    /// service, matching the group's pending commit.
    ///
    /// This is returned instead of
    /// [`StagedCommitMessage`](Self::StagedCommitMessage) when the processed
    /// Commit was created by this client and matches the group's pending commit.
    /// Since this client already holds the corresponding pending commit, the
    /// incoming Commit is not staged. To apply it, merge the pending commit
    /// using
    /// [`MlsGroup::merge_pending_commit()`](crate::group::mls_group::MlsGroup::merge_pending_commit()).
    /// An own Commit that does not match the pending commit is instead returned
    /// as a [`StagedCommitMessage`](Self::StagedCommitMessage) (if it has no
    /// UpdatePath) or rejected (if it has an UpdatePath we cannot decrypt).
    ///
    /// The match against the pending commit is established by comparing the
    /// confirmation tag of the incoming Commit against the one stored with the
    /// pending commit. The message signature has already been verified, which
    /// authenticates the Commit as ours, and a matching confirmation tag binds
    /// the confirmed transcript hash of the new epoch. We do not otherwise
    /// compare the contents of the incoming Commit against the pending commit,
    /// and the incoming Commit's state is never adopted.
    ///
    /// This is only produced for Commits framed as
    /// [`PublicMessage`](crate::framing::MlsMessageBodyIn::PublicMessage). A
    /// Commit framed as a
    /// [`PrivateMessage`](crate::framing::MlsMessageBodyIn::PrivateMessage)
    /// cannot be decrypted by its own author and instead surfaces as
    /// [`OwnPrivateMessage`](Self::OwnPrivateMessage). The exception is the
    /// `virtual-clients-draft` feature, where an own private Commit whose
    /// encryption secret is still retained (not yet confirmed) decrypts and
    /// can produce this variant as well.
    OwnPendingCommit,
    /// A PrivateMessage whose sender data claims this client's own leaf index,
    /// i.e. a message this client authored that the delivery service fanned
    /// back.
    ///
    /// The content cannot be decrypted (the own sender ratchet is
    /// encryption-only) and the signature cannot be verified.
    ///
    /// Applications should treat this variant as a hint to skip the message.
    /// The content type of the incoming message (application/proposal/commit)
    /// is available via `ProtocolMessage::content_type()` before processing,
    /// and is unauthenticated plaintext in the PrivateMessage framing.
    ///
    /// With the `virtual-clients-draft` feature, own-leaf messages are
    /// decryptable while their secrets are retained: unconfirmed own sends
    /// and messages from sibling emulator clients decrypt and process
    /// normally. This variant is then only returned in groups that do not
    /// use virtual clients (no emulation state registered for the message's
    /// epoch), when decryption of an own message fails, e.g. because the
    /// send was already confirmed via `MlsGroup::confirm_message()`.
    OwnPrivateMessage,
    /// A Commit message covering AppDataUpdate proposals.
    ///
    /// The proposals carry diffs in an application-defined format, so the
    /// commit cannot be staged before the application has interpreted them and
    /// computed the resulting dictionary entries. Inspect the proposals via
    /// [`UnresolvedAppDataCommit::app_data_update_proposals()`], compute the
    /// updates with the help of
    /// [`MlsGroup::app_data_dictionary_updater()`](crate::group::mls_group::MlsGroup::app_data_dictionary_updater)
    /// and resume staging via
    /// [`MlsGroup::stage_app_data_commit()`](crate::group::mls_group::MlsGroup::stage_app_data_commit).
    ///
    /// This variant is likewise returned by
    /// [`PublicGroup::process_message()`](crate::group::public_group::PublicGroup::process_message),
    /// where the updates are computed with
    /// [`PublicGroup::app_data_dictionary_updater()`](crate::group::public_group::PublicGroup::app_data_dictionary_updater)
    /// and staging resumes via
    /// [`PublicGroup::stage_app_data_commit()`](crate::group::public_group::PublicGroup::stage_app_data_commit).
    #[cfg(feature = "extensions-draft")]
    UnresolvedAppDataCommit(Box<UnresolvedAppDataCommit>),
}

/// Application message received through a [ProcessedMessage].
#[derive(Debug, PartialEq, Eq)]
pub struct ApplicationMessage {
    bytes: Vec<u8>,
}

impl ApplicationMessage {
    /// Create a new [ApplicationMessage].
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the inner bytes and consumes the [`ApplicationMessage`].
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
