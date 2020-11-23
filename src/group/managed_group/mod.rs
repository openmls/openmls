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
#[allow(dead_code)]
pub struct ManagedGroup {
    managed_group_config: ManagedGroupConfig,
    group: MlsGroup,
    proposal_queue: ProposalQueue,
    own_kpbs: Vec<KeyPackageBundle>,
}

#[allow(unused_variables)]
impl ManagedGroup {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member.
    pub fn new(
        credential_bundle: &CredentialBundle,
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
            proposal_queue: ProposalQueue::new(),
            own_kpbs: vec![],
        })
    }

    /// Creates a new group from a `Welcome` message
    pub fn new_from_welcome(
        credential_bundle: &CredentialBundle,
        managed_group_config: &ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, WelcomeError> {
        let group = MlsGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle)?;
        Ok(ManagedGroup {
            managed_group_config: managed_group_config.clone(),
            group,
            proposal_queue: ProposalQueue::new(),
            own_kpbs: vec![],
        })
    }

    // === Membership management ===

    /// Adds members to the group
    pub fn add_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        key_packages: &[KeyPackage],
    ) -> Result<(Vec<MLSMessage>, Welcome), ManagedGroupError> {
        unimplemented!()
    }

    /// Removes members from the group
    pub fn remove_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        unimplemented!()
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        key_packages: &[KeyPackage],
    ) -> Result<(Vec<MLSMessage>, Welcome), ManagedGroupError> {
        unimplemented!()
    }

    /// Creates proposals to remove members from the group
    pub fn propose_remove_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        unimplemented!()
    }

    /// Gets the current list of members
    pub fn get_members(&self) -> &[Credential] {
        unimplemented!()
    }

    // === Process messages ===

    /// Processes any incoming messages from the DS (MLSPlaintext &
    /// MLSCiphertext) and triggers the corresponding callback functions
    pub fn process_messages(&mut self, messages: &[MLSMessage]) {
        unimplemented!()
    }

    // === Create application messages ===

    /// Create an application message
    pub fn create_message(
        &mut self,
        credential_bundle: &CredentialBundle,
        message: &[u8],
    ) -> MLSMessage {
        unimplemented!()
    }

    // === Export secrets ===

    /// Exports a secret from the current epoch
    pub fn export_secret(&self, label: &[u8]) -> Vec<u8> {
        unimplemented!()
    }

    // === Configuration ===

    /// Gets the configuration
    pub fn configuration(&self) -> &ManagedGroupConfig {
        unimplemented!()
    }

    /// Sets the configuration
    pub fn set_configuration(&mut self, managed_group_config: &ManagedGroupConfig) {
        unimplemented!()
    }

    /// Gets the AAD used in the framing
    pub fn aad(&self) -> &[u8] {
        unimplemented!()
    }

    /// Sets the AAD used in the framing
    pub fn set_aad(&mut self, aad: &[u8]) {
        unimplemented!()
    }

    // === Advanced functions ===

    /// Updates the own leaf node
    pub fn self_update(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        unimplemented!()
    }

    /// Creates a proposal to update the own leaf node
    pub fn propose_self_update(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        unimplemented!()
    }

    /// Returns a list of proposal
    pub fn get_pending_proposals(&self) -> Vec<Proposal> {
        unimplemented!()
    }

    // === Load & save ===

    /// Loads the state from persisted state
    pub fn load(reader: Box<dyn Read>, managed_group_config: &ManagedGroupConfig) -> ManagedGroup {
        unimplemented!()
    }

    /// Persists the state
    pub fn save(&self, writer: Box<dyn Write>) {}

    // === Interface for callbacks ===

    /// Get group ID
    pub fn group_id(&self) -> &GroupId {
        unimplemented!()
    }

    /// Get client ID
    pub fn client_id(&self) -> &[u8] {
        unimplemented!()
    }

    /// Get credential from LeafIndex
    pub fn member(&self, leaf_index: LeafIndex) -> &Credential {
        unimplemented!()
    }

    // === Extensions ===

    /// Export the Ratchet Tree
    pub fn export_ratchet_tree(&self) -> Vec<Option<Node>> {
        unimplemented!()
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
#[derive(Clone)]
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
    Codec(CodecError),
    Config(ConfigError),
    UseAfterEviction,
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
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender, aad_porposal:
/// &AddProposal) -> bool`
pub type ValidateAdd = fn(&ManagedGroup, &[u8], &Sender, &AddProposal) -> bool;
/// Validator function for RemoveProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Sender,
/// remove_porposal: &RemoveProposal) -> bool`
pub type ValidateRemove = fn(&ManagedGroup, &[u8], &Sender, &RemoveProposal) -> bool;
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
/// `(managed_group: &ManagedGroup, aad_option: Option<&[u8]>, sender_option:
/// Option<&Sender>, error: InvalidMessageError)`
pub type InvalidMessageReceived =
    fn(&ManagedGroup, Option<&[u8]>, Option<&Sender>, InvalidMessageError);
/// Event listener function for errors that occur
/// `(managed_group: &ManagedGroup, error: ManagedGroupError)`
pub type ErrorOccured = fn(&ManagedGroup, ManagedGroupError);

#[derive(Debug)]
pub enum InvalidMessageError {
    Unknown,
}

implement_enum_display!(InvalidMessageError);

impl Error for InvalidMessageError {
    fn description(&self) -> &str {
        match self {
            Self::Unknown => "Unknown error.",
        }
    }
}
