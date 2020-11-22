use crate::codec::*;
use crate::config::ConfigError;
use crate::creds::{Credential, CredentialBundle};
use crate::framing::{sender::*, *};
use crate::group::*;
use crate::key_packages::{KeyPackage, KeyPackageBundle};
use crate::messages::{proposals::*, Welcome};
use crate::tree::index::LeafIndex;
use crate::tree::node::Node;

use std::error::Error;
use std::io::{Read, Write};

/// A `ManagedGroup` represents an `MLSGroup` with an easier, high-level API
/// designed to be used in production. The API exposes high level functions to
/// manage a group by adding/removing members, get the current member list, etc.
///
/// The API is modeled such that it can serve as a direct interface to the
/// Delivery Service. Functions that modify the public state of the group will
/// return a `Vec<MLSMessage>` that can be sent to the Delivery Service
/// directly. Conversely, incoming messages from the Delivery Service can be fed
/// into `process_nessage()`.
///
/// A `ManagedGroup` has an internal queue of pending proposals that builds up
/// as new messages are processed. When creating proposals, those messages are
/// not automatically appended to this queue, instead they have to be processed
/// again through `process_message()`. This allows the Delivery Service to
/// reject them (e.g. if they reference the wrong epoch).
///
/// If incoming messages or applied operations are semantically or syntactically
/// incorrect, a callback function will be called with a corresponding error
/// message and the state of the group will remain unchanged.
///
/// The application policy for the group can be enforced by implementing the
/// validator callback functions and selectively allowing/ disallowing each
/// operation (see `ManagedGroupCallbacks`)
///
/// Changes to the group state are dispatched as events through callback
/// functions (see ManagedGroupCallbacks).
pub struct ManagedGroup {
    managed_group_config: ManagedGroupConfig,
    group: MlsGroup,
    pending_proposals: Vec<MLSPlaintext>,
    own_kpbs: Vec<KeyPackageBundle>,
    aad: Vec<u8>,
    active: bool,
}

impl ManagedGroup {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member.
    pub fn new(
        managed_group_config: &ManagedGroupConfig,
        group_id: GroupId,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, ManagedGroupError> {
        let group = MlsGroup::new(
            &group_id.as_slice(),
            key_package_bundle.get_key_package().cipher_suite().name(),
            key_package_bundle,
            GroupConfig::default(),
        )?;

        Ok(ManagedGroup {
            managed_group_config: managed_group_config.clone(),
            group,
            pending_proposals: vec![],
            own_kpbs: vec![],
            aad: vec![],
            active: true,
        })
    }

    /// Creates a new group from a `Welcome` message
    pub fn new_from_welcome(
        managed_group_config: &ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, WelcomeError> {
        let group = MlsGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle)?;
        Ok(ManagedGroup {
            managed_group_config: managed_group_config.clone(),
            group,
            pending_proposals: vec![],
            own_kpbs: vec![],
            aad: vec![],
            active: true,
        })
    }

    // === Membership management ===

    /// Adds members to the group
    pub fn add_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        key_packages: &[KeyPackage],
    ) -> Result<(Vec<MLSMessage>, Welcome), ManagedGroupError> {
        // Create framed add proposals from key packages
        let mut plaintext_messages: Vec<MLSPlaintext> = key_packages
            .iter()
            .map(|key_package| {
                self.group
                    .create_add_proposal(&[], &credential_bundle, key_package.clone())
            })
            .collect();

        // Include pending proposals into Commit
        let mut messages_to_commit = self.pending_proposals.clone();
        messages_to_commit.extend_from_slice(&plaintext_messages);

        // Create Commit over all proposals
        let (commit, welcome_option, kpb_option) =
            self.group
                .create_commit(&[], &credential_bundle, &messages_to_commit, false)?;

        // Add the Commit message to the other pending messages
        plaintext_messages.append(&mut vec![commit]);

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        let welcome = match welcome_option {
            Some(welcome) => welcome,
            None => return Err(ManagedGroupError::Unknown),
        };
        Ok((mls_messages, welcome))
    }

    /// Removes members from the group
    pub fn remove_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        let mut plaintext_messages: Vec<MLSPlaintext> = members
            .iter()
            .map(|member| {
                self.group
                    .create_remove_proposal(&[], &credential_bundle, LeafIndex::from(*member))
            })
            .collect();

        // Include pending proposals into Commit
        let mut messages_to_commit = self.pending_proposals.clone();
        messages_to_commit.extend_from_slice(&plaintext_messages);

        // Create Commit over all proposals
        let (commit, _, kpb_option) =
            self.group
                .create_commit(&[], &credential_bundle, &messages_to_commit, false)?;

        // Add the Commit message to the other pending messages
        plaintext_messages.append(&mut vec![commit]);

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        key_packages: &[KeyPackage],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        let plaintext_messages: Vec<MLSPlaintext> = key_packages
            .iter()
            .map(|key_package| {
                self.group
                    .create_add_proposal(&[], &credential_bundle, key_package.clone())
            })
            .collect();

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Creates proposals to remove members from the group
    pub fn propose_remove_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        let plaintext_messages: Vec<MLSPlaintext> = members
            .iter()
            .map(|member| {
                self.group
                    .create_remove_proposal(&[], &credential_bundle, LeafIndex::from(*member))
            })
            .collect();

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Leave the group
    pub fn leave_group(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        let remove_proposal = self.group.create_remove_proposal(
            &[],
            &credential_bundle,
            LeafIndex::from(self.group.tree().get_own_node_index()),
        );

        let mls_messages = self.plaintext_to_mls_messages(vec![remove_proposal]);

        Ok(mls_messages)
    }

    /// Gets the current list of members
    pub fn get_members(&self) -> Vec<Credential> {
        let mut members: Vec<Credential> = vec![];
        let tree = self.group.tree();
        let leaf_count = self.group.tree().leaf_count();
        for index in 0..leaf_count.as_usize() {
            let leaf = &tree.nodes[LeafIndex::from(index)];
            if let Some(leaf_node) = leaf.get_key_package_ref() {
                members.push(leaf_node.credential().clone());
            }
        }
        members
    }

    // === Process messages ===

    /// Processes any incoming messages from the DS (MLSPlaintext &
    /// MLSCiphertext) and triggers the corresponding callback functions
    pub fn process_messages(&mut self, messages: &[MLSMessage]) {
        // Iterate over all incoming messages
        for message in messages {
            // Check the type of message we recived
            let (plaintext_option, aad_option) = match message {
                // If it is a ciphertext we decrypt it and return the plaintext by value
                MLSMessage::Ciphertext(ciphertext) => {
                    let aad = &ciphertext.authenticated_data;
                    match self.group.decrypt(ciphertext) {
                        Ok(plaintext) => (Some(ValueOrRef::from(plaintext)), Some(aad)),
                        Err(_) => {
                            // If there is a callback for that event we should call it
                            self.invalid_message_event(InvalidMessageError::InvalidCiphertext(
                                aad.to_vec(),
                            ));
                            (None, Some(aad))
                        }
                    }
                }
                // If it is a plaintext message we just return the reference
                MLSMessage::Plaintext(plaintext) => (Some(ValueOrRef::from(plaintext)), None),
            };
            // If it was a plaintext message or if the decryption succeeded we continue,
            // otherwise we move to the next message
            if let Some(plaintext) = plaintext_option {
                // See what kind of message it is
                match plaintext.to_ref().content {
                    MLSPlaintextContentType::Proposal(_) => {
                        // Incoming proposals are validated against the application validation
                        // policy and then appended to the internal `pending_proposal` list.
                        // TODO #133: Semantic validation of proposals
                        if self.validate_proposal(plaintext.to_ref()) {
                            self.pending_proposals.push(plaintext.into_value_or_clone());
                        } else {
                            self.invalid_message_event(
                                InvalidMessageError::CommitWithInvalidProposals,
                            );
                        }
                    }
                    MLSPlaintextContentType::Commit(_) => {
                        // If all proposals were valid, we continue with applying the Commit
                        // message
                        match self.group.apply_commit(
                            plaintext.into_value_or_clone(),
                            self.pending_proposals.clone(),
                            &self.own_kpbs,
                        ) {
                            Ok(()) => {
                                // Since the Commit was applied without errors,
                                // we can can call all corresponding callback
                                // functions for the whole proposal list
                                self.send_events();
                                // We don't meed the pending proposals any longer
                                self.pending_proposals = vec![];
                            }
                            Err(apply_commit_error) => match apply_commit_error {
                                ApplyCommitError::SelfRemoved => {
                                    self.active = false;
                                }
                                _ => {
                                    self.invalid_message_event(InvalidMessageError::CommitError(
                                        apply_commit_error,
                                    ));
                                }
                            },
                        }
                    }
                    MLSPlaintextContentType::Application(ref app_message) => {
                        // If there is a callback for that event we should call it
                        if let Some(app_message_received) =
                            self.managed_group_config.callbacks.app_message_received
                        {
                            app_message_received(
                                &self,
                                aad_option.unwrap(),
                                &plaintext.to_ref().sender,
                                app_message,
                            );
                        }
                    }
                }
            }
        }
    }

    // === Application messages ===

    /// Creates an application message.  
    /// Returns `ManagedGroupError::UseAfterEviction` if the member is no longer
    /// part of the group. Returns `ManagedGroupError::
    /// PendingProposalsExist` if pending proposals exist. In that case
    /// `.flush_proposals()` must be called first and incoming messages from the
    /// DS must be processed afterwards.
    pub fn create_message(
        &mut self,
        credential_bundle: &CredentialBundle,
        message: &[u8],
    ) -> Result<MLSMessage, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        if !self.pending_proposals.is_empty() {
            return Err(ManagedGroupError::PendingProposalsExist);
        }
        let ciphertext =
            self.group
                .create_application_message(&self.aad, message, credential_bundle);
        Ok(MLSMessage::Ciphertext(ciphertext))
    }

    /// Flush pending proposals
    pub fn flush_proposals(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        // Include pending proposals into Commit
        let mut plaintext_messages = self.pending_proposals.clone();

        // Create Commit over all proposals
        let (commit, _, kpb_option) =
            self.group
                .create_commit(&[], &credential_bundle, &plaintext_messages, false)?;

        // Add the Commit message to the other pending messages
        plaintext_messages.append(&mut vec![commit]);

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    // === Export secrets ===

    /// Exports a secret from the current epoch
    pub fn export_secret(&self, label: &str, key_length: usize) -> Vec<u8> {
        self.group.export_secret(label, key_length).to_vec()
    }

    // === Configuration ===

    /// Gets the configuration
    pub fn configuration(&self) -> &ManagedGroupConfig {
        &self.managed_group_config
    }

    /// Sets the configuration
    pub fn set_configuration(&mut self, managed_group_config: &ManagedGroupConfig) {
        self.managed_group_config = managed_group_config.clone()
    }

    /// Gets the AAD used in the framing
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Sets the AAD used in the framing
    pub fn set_aad(&mut self, aad: &[u8]) {
        self.aad = aad.to_vec()
    }

    // === Advanced functions ===

    /// Updates the own leaf node
    pub fn self_update(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        let tree = self.group.tree();
        let existing_key_package = tree.get_own_key_package_ref();
        let key_package_bundle = KeyPackageBundle::from_rekeyed_key_package(existing_key_package);

        let mut plaintext_messages = vec![self.group.create_update_proposal(
            &self.aad,
            credential_bundle,
            key_package_bundle.get_key_package().clone(),
        )];
        let (commit, _welcome_option, kpb_option) =
            self.group
                .create_commit(&[], &credential_bundle, &plaintext_messages, false)?;
        plaintext_messages.append(&mut vec![commit]);
        drop(tree);

        let kpb = match kpb_option {
            Some(kpb) => kpb,
            None => return Err(ManagedGroupError::Unknown),
        };
        self.own_kpbs.push(kpb);

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Creates a proposal to update the own leaf node
    pub fn propose_self_update(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        let tree = self.group.tree();
        let existing_key_package = tree.get_own_key_package_ref();
        let key_package_bundle = KeyPackageBundle::from_rekeyed_key_package(existing_key_package);

        let plaintext_messages = vec![self.group.create_update_proposal(
            &self.aad,
            credential_bundle,
            key_package_bundle.get_key_package().clone(),
        )];
        drop(tree);

        self.own_kpbs.push(key_package_bundle);

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Returns a list of proposal
    pub fn get_pending_proposals(&self) -> &[MLSPlaintext] {
        &self.pending_proposals
    }

    // === Load & save ===

    /// Loads the state from persisted state
    pub fn load(
        _reader: Box<dyn Read>,
        _managed_group_config: &ManagedGroupConfig,
    ) -> ManagedGroup {
        unimplemented!()
    }

    /// Persists the state
    pub fn save(&self, _writer: Box<dyn Write>) {}

    // === Interface for callbacks ===

    /// Get group ID
    pub fn group_id(&self) -> &GroupId {
        self.group.group_id()
    }

    /// Get client ID
    pub fn client_id(&self) -> Vec<u8> {
        self.group
            .tree()
            .get_own_key_package_ref()
            .credential()
            .get_identity()
            .to_vec()
    }

    /// Get credential from LeafIndex
    pub fn member(&self, leaf_index: LeafIndex) -> Option<Credential> {
        match self.group.tree().nodes[leaf_index]
            .get_key_package_ref()
            .as_ref()
        {
            Some(key_package) => Some(key_package.credential().clone()),
            None => None,
        }
    }

    // === Extensions ===

    /// Export the Ratchet Tree
    pub fn export_ratchet_tree(&self) -> Vec<Option<Node>> {
        self.group.tree().public_key_tree_copy()
    }
}

// Private methods of ManagedGroup
impl ManagedGroup {
    /// Converts MLSPlaintext to MLSMessage. Depending on whether handshake
    /// message should be encrypted, MLSPlaintext messages are encrypted to
    /// MLSCiphertext first.
    fn plaintext_to_mls_messages(
        &mut self,
        plaintext_messages: Vec<MLSPlaintext>,
    ) -> Vec<MLSMessage> {
        plaintext_messages
            .into_iter()
            .map(|plaintext| match self.configuration().encrypt_hs_messages {
                HandshakeMessageFormat::Plaintext => MLSMessage::Plaintext(plaintext),
                HandshakeMessageFormat::Ciphertext => {
                    let ciphertext = self.group.encrypt(plaintext);
                    MLSMessage::Ciphertext(ciphertext)
                }
            })
            .collect()
    }

    /// Validate all pending proposals. The function returns `true` only if all
    /// proposals are valid.
    fn validate_proposal(&self, framed_proposal: &MLSPlaintext) -> bool {
        match framed_proposal.content {
            MLSPlaintextContentType::Proposal(ref proposal) => match proposal {
                // Validate add proposals
                Proposal::Add(add_proposal) => {
                    if let Some(validate_add) = self.managed_group_config.callbacks.validate_add {
                        if !validate_add(&self, &framed_proposal.sender, add_proposal) {
                            return false;
                        }
                    }
                }
                // Validate remove proposals
                Proposal::Remove(remove_proposal) => {
                    if let Some(validate_remove) =
                        self.managed_group_config.callbacks.validate_remove
                    {
                        if !validate_remove(&self, &framed_proposal.sender, remove_proposal) {
                            return false;
                        }
                    }
                }
                // Update proposals don't have validators
                Proposal::Update(_) => {}
            },
            // Other content types should not be in here
            _ => {
                panic!("Library error: pending_proposals should only contain proposals")
            }
        }
        true
    }

    /// Send out the corresponding events for the pending proposal list.
    fn send_events(&self) {
        for framed_proposal in &self.pending_proposals {
            match framed_proposal.content {
                MLSPlaintextContentType::Proposal(ref proposal) => match proposal {
                    // Add proposals
                    Proposal::Add(add_proposal) => {
                        if let Some(member_added) = self.managed_group_config.callbacks.member_added
                        {
                            member_added(&self, &[], &framed_proposal.sender, add_proposal)
                        }
                    }
                    // Update proposals
                    Proposal::Update(update_proposal) => {
                        if let Some(member_updated) =
                            self.managed_group_config.callbacks.member_updated
                        {
                            member_updated(&self, &[], &framed_proposal.sender, update_proposal)
                        }
                    }
                    // Remove proposals
                    Proposal::Remove(remove_proposal) => {
                        if let Some(member_removed) =
                            self.managed_group_config.callbacks.member_removed
                        {
                            member_removed(&self, &[], &framed_proposal.sender, remove_proposal)
                        }
                    }
                },
                // Other content types should not be in here
                _ => {
                    panic!("Library error: pending_proposals should only contain proposals")
                }
            }
        }
    }

    /// Send an event when an invalid message was received
    fn invalid_message_event(&self, error: InvalidMessageError) {
        if let Some(invalid_message_received) =
            self.managed_group_config.callbacks.invalid_message_received
        {
            invalid_message_received(&self, error);
        }
    }
}

#[derive(Clone)]
pub enum HandshakeMessageFormat {
    Plaintext,
    Ciphertext,
}
/// Specifies the configuration parameters for a managed group
#[derive(Clone)]
pub struct ManagedGroupConfig {
    /// Defines whether handshake messages should be encrypted
    encrypt_hs_messages: HandshakeMessageFormat,
    /// Defines the update policy
    update_policy: UpdatePolicy,
    /// Callbacks
    callbacks: ManagedGroupCallbacks,
}

impl ManagedGroupConfig {
    pub fn new(
        encrypt_hs_messages: HandshakeMessageFormat,
        update_policy: UpdatePolicy,
        callbacks: ManagedGroupCallbacks,
    ) -> Self {
        ManagedGroupConfig {
            encrypt_hs_messages,
            update_policy,
            callbacks,
        }
    }
}

/// Specifies in which intervals the own leaf node should be updated
#[derive(Clone)]
pub struct UpdatePolicy {
    /// Maximum time before an update in seconds
    maximum_time: u32,
    /// Maximum messages that are sent before an update in seconds
    maximum_sent_messages: u32,
    /// Maximum messages that are received before an update in seconds
    maximum_received_messages: u32,
}

impl Default for UpdatePolicy {
    fn default() -> Self {
        UpdatePolicy {
            maximum_time: 2_592_000, // 30 days in seconds
            maximum_sent_messages: 100,
            maximum_received_messages: 1_000,
        }
    }
}

/// Unified message type
#[derive(Debug, Clone)]
pub enum MLSMessage {
    Plaintext(MLSPlaintext),
    Ciphertext(MLSCiphertext),
}

impl From<MLSPlaintext> for MLSMessage {
    fn from(mls_plaintext: MLSPlaintext) -> Self {
        MLSMessage::Plaintext(mls_plaintext)
    }
}

impl From<MLSCiphertext> for MLSMessage {
    fn from(mls_ciphertext: MLSCiphertext) -> Self {
        MLSMessage::Ciphertext(mls_ciphertext)
    }
}

#[derive(Debug)]
pub enum ManagedGroupError {
    Unknown,
    Codec(CodecError),
    Config(ConfigError),
    Group(GroupError),
    CreateCommit(CreateCommitError),
    UseAfterEviction,
    PendingProposalsExist,
}

impl From<ConfigError> for ManagedGroupError {
    fn from(err: ConfigError) -> ManagedGroupError {
        ManagedGroupError::Config(err)
    }
}

impl From<CodecError> for ManagedGroupError {
    fn from(err: CodecError) -> ManagedGroupError {
        ManagedGroupError::Codec(err)
    }
}

impl From<GroupError> for ManagedGroupError {
    fn from(err: GroupError) -> ManagedGroupError {
        ManagedGroupError::Group(err)
    }
}

impl From<CreateCommitError> for ManagedGroupError {
    fn from(err: CreateCommitError) -> ManagedGroupError {
        ManagedGroupError::CreateCommit(err)
    }
}

#[derive(Debug)]
pub enum InvalidMessageError {
    InvalidCiphertext(Vec<u8>),
    CommitWithInvalidProposals,
    CommitError(ApplyCommitError),
}

implement_enum_display!(InvalidMessageError);

impl Error for InvalidMessageError {
    fn description(&self) -> &str {
        match self {
            Self::InvalidCiphertext(_) => "Invalid ciphertext received",
            Self::CommitWithInvalidProposals => {
                "A Commit message referencing one or more invalid proposals was received"
            }
            Self::CommitError(_) => "An error occured when applying a Commit message",
        }
    }
}

/// Collection of callback functions that are passed to a `ManagedGroup` as part
/// of the configurations Callback functions are optional. If no validator
/// function is specified for a certain proposal type, any semantically valid
/// proposal will be accepted. Validator fucntions returan a `bool`, depending
/// on whether the proposal is accepted by the application policy.
///  - `true` means the proposal should be accepted
///  - `false` means the proposal should be rejected
#[derive(Clone)]
pub struct ManagedGroupCallbacks {
    // Validator functions
    validate_add: Option<ValidateAdd>,
    validate_remove: Option<ValidateRemove>,
    // Event listeners
    member_added: Option<MemberAdded>,
    member_removed: Option<MemberRemoved>,
    member_updated: Option<MemberUpdated>,
    app_message_received: Option<AppMessageReceived>,
    invalid_message_received: Option<InvalidMessageReceived>,
    error_occured: Option<ErrorOccured>,
}

#[allow(clippy::too_many_arguments)]
impl ManagedGroupCallbacks {
    pub fn new(
        validate_add: Option<ValidateAdd>,
        validate_remove: Option<ValidateRemove>,
        member_added: Option<MemberAdded>,
        member_removed: Option<MemberRemoved>,
        member_updated: Option<MemberUpdated>,
        app_message_received: Option<AppMessageReceived>,
        invalid_message_received: Option<InvalidMessageReceived>,
        error_occured: Option<ErrorOccured>,
    ) -> Self {
        Self {
            validate_add,
            validate_remove,
            member_added,
            member_removed,
            member_updated,
            app_message_received,
            invalid_message_received,
            error_occured,
        }
    }
}

/// Validator function for AddProposals
/// `(managed_group: &ManagedGroup, sender: &Sender, aad_porposal:
/// &AddProposal) -> bool`
pub type ValidateAdd = fn(&ManagedGroup, &Sender, &AddProposal) -> bool;
/// Validator function for RemoveProposals
/// `(managed_group: &ManagedGroup, sender: &Sender,
/// remove_porposal: &RemoveProposal) -> bool`
pub type ValidateRemove = fn(&ManagedGroup, &Sender, &RemoveProposal) -> bool;
/// Event listener function for AddProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender, add_proposal:
/// &AddProposal)`
pub type MemberAdded = fn(&ManagedGroup, &[u8], &Sender, &AddProposal);
/// Event listener function for RemoveProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender,
/// remove_proposal: &RemoveProposal)`
pub type MemberRemoved = fn(&ManagedGroup, &[u8], &Sender, &RemoveProposal);
/// Event listener function for UpdateProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender,
/// update_proposal: &UpdateProposal)`
pub type MemberUpdated = fn(&ManagedGroup, &[u8], &Sender, &UpdateProposal);
/// Event listener function for application messages
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender, message:
/// &[u8])`
pub type AppMessageReceived = fn(&ManagedGroup, &[u8], &Sender, &[u8]);
/// Event listener function for invalid messages
/// `(managed_group: &ManagedGroup, error: InvalidMessageError)`
pub type InvalidMessageReceived = fn(&ManagedGroup, InvalidMessageError);
/// Event listener function for errors that occur
/// `(managed_group: &ManagedGroup, error: ManagedGroupError)`
pub type ErrorOccured = fn(&ManagedGroup, ManagedGroupError);
