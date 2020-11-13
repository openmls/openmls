use crate::ciphersuite::*;
use crate::codec::*;
use crate::creds::*;
use crate::errors::ConfigError;
use crate::framing::{sender::*, *};
use crate::group::*;
use crate::key_packages::*;
use crate::messages::{proposals::*, *};
use crate::tree::node::*;

/// A `ManagedGroup` represents an `MLSGroup` with an easier, high-level API designed to be used in production. The API
/// exposes high level functions to manage a group by adding/removing members, get the current member list, etc.
///
/// The API is modelled such that it can serve as a direct interface to the Delivery Serive. Functions that modify the public state
/// of the group will return a `Vec<MLSMessage>` that can be sent to the Delivery Service directly. Conversely, incoming messages
/// from the Delivery Service can be fed into `process_nessage()`.
///
/// A `ManagedGroup` has an internal queue of pending proposals that builds up as new messages are processed. When creating proposals,
/// those messages are not automatically appended to this queue, instead they have be processed again through `process_message()`.
/// This allows the Delivery Service to reject them (e.g. if they reference the wrong epoch).
///
/// If incoming messages or applied operations are semantically or syntactily incorrect, the function will return a corresponding
/// error message and the state of the group will remain unchanged.
///
/// The application policy for the group can be enforced by implementing the validator callback functions and selectively allowing/
/// disallowing each operation (see `ManagedGroupCallbacks`)
///
/// Changes to the group state are dispatched as events through callback functions (see ManagedGroupCallbacks).
pub struct ManagedGroup {
    managed_group_config: ManagedGroupConfig,
    group: MlsGroup,
    proposal_queue: ProposalQueue,
    own_kpbs: Vec<KeyPackageBundle>,
}

impl ManagedGroup {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member.
    pub fn new(
        credential_bundle: &CredentialBundle,
        managed_group_config: &ManagedGroupConfig,
        group_id: GroupId,
        ciphersuite_name: CiphersuiteName,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, GroupError> {
        let group = MlsGroup::new(
            &group_id.as_slice(),
            ciphersuite_name,
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

    /// Creates a new group with the creator and additional members
    pub fn new_with_members(
        credential_bundle: &CredentialBundle,
        managed_group_config: &ManagedGroupConfig,
        group_id: GroupId,
        ciphersuite_name: CiphersuiteName,
        key_package_bundle: KeyPackageBundle,
        members: Vec<KeyPackage>,
    ) -> Result<Self, GroupError> {
        unimplemented!()
    }

    // === Membership management ===

    /// Adds members to the group
    pub fn add_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        aad: &[u8],
        key_packages: Vec<KeyPackage>,
    ) -> Result<Vec<MLSMessage>, GroupError> {
        unimplemented!()
    }

    /// Removes members from the group
    pub fn remove_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        aad: &[u8],
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, GroupError> {
        unimplemented!()
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        aad: &[u8],
        key_packages: Vec<KeyPackage>,
    ) -> Result<Vec<MLSMessage>, GroupError> {
        unimplemented!()
    }

    /// Creates proposals to remove members from the group
    pub fn propose_remove_members(
        &mut self,
        credential_bundle: &CredentialBundle,
        aad: &[u8],
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, GroupError> {
        unimplemented!()
    }

    /// Gets the current list of members
    pub fn get_members(&self) -> &[Credential] {
        unimplemented!()
    }

    // === Process messages ===

    /// Processes any incoming message from the DS (MLSPlaintext & MLSCiphertext) and triggers the corresponding callback functions
    pub fn process_message(&mut self, message: MLSMessage) {
        unimplemented!()
    }

    // === Create application messages ===

    /// Create an application message
    pub fn create_message(
        &mut self,
        credential_bundle: &CredentialBundle,
        aad: &[u8],
        message: &[u8],
    ) {
        unimplemented!()
    }

    // === Export secrets ===

    /// Exports a secret from the current epoch
    pub fn export_secret(&self) -> Vec<u8> {
        unimplemented!()
    }

    // === Advanced functions ===

    /// Updates the own leaf node
    pub fn self_update(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Vec<MLSMessage>, GroupError> {
        unimplemented!()
    }

    /// Creates a proposal to update the own leaf node
    pub fn propose_self_update(
        &mut self,
        credential_bundle: &CredentialBundle,
    ) -> Result<Vec<MLSMessage>, GroupError> {
        unimplemented!()
    }

    /// Returns a list of proposal
    pub fn get_pending_proposals(&self) -> Vec<Proposal> {
        unimplemented!()
    }

    // === Load & save (WIP) ===

    /// Loads the state from persisted state
    pub fn load(state: &[u8], managed_group_config: &ManagedGroupConfig) -> ManagedGroup {
        unimplemented!()
    }

    /// Persists the state
    pub fn save(&self, state: &mut Vec<u8>) {}
}
/// Specifies the configuration parameters for a managed group
#[derive(Clone)]
pub struct ManagedGroupConfig {
    /// Defines whether handshake messages should be encrypted
    encrypt_hs_messages: bool,
    /// Defines the update policy
    update_policy: UpdatePolicy,
    /// Callbacks
    callbacks: ManagedGroupCallbacks,
}

/// Specifies at which intervals the own leaf node should be updates
#[derive(Clone)]
pub struct UpdatePolicy {
    /// Maximum time before an update in seconds
    maximum_time: u32,
    /// Maximum messages that are sent before an update in seconds
    maximum_sent_messages: u32,
    /// Maximum messages that are received before an update in seconds
    maximum_received_messages: u32,
}

pub enum MLSMessage {
    Plaintext(MLSPlaintext),
    Ciphertext(MLSCiphertext),
}

pub enum GroupError {
    Codec(CodecError),
    Config(ConfigError),
}

impl From<ConfigError> for GroupError {
    fn from(err: ConfigError) -> GroupError {
        GroupError::Config(err)
    }
}

impl From<CodecError> for GroupError {
    fn from(err: CodecError) -> GroupError {
        GroupError::Codec(err)
    }
}

/// Collection of callback functions that are passed to a `ManagedGroup` as part of the configurations
/// Callback functions are optional. If no validator function is specified for a certain proposal type, any
/// semantically valid proposal will be accepted.
/// Validator fucntions returan a `bool`, epending on whether the proposal is accepted by the application policy.
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
}

/// Validator function for AddProposals
/// `(managed_group: &ManagedGroup, sender: &Sender, aad_porposal: &AddProposal) -> bool`
pub type ValidateAdd = fn(&ManagedGroup, &Sender, &AddProposal) -> bool;
/// Validator function for RemoveProposals
/// `(managed_group: &ManagedGroup, sender: &Sender, remove_porposal: &RemoveProposal) -> bool`
pub type ValidateRemove = fn(&ManagedGroup, &Sender, &RemoveProposal) -> bool;
/// Event listener function for AddProposals
/// `(managed_group: &ManagedGroup, sender: &Sender, aad_porposal: &AddProposal)`
pub type MemberAdded = fn(&ManagedGroup, &Sender, &AddProposal);
/// Event listener function for RemoveProposals
/// `(managed_group: &ManagedGroup, sender: &Sender, remove_porposal: &RemoveProposal)`
pub type MemberRemoved = fn(&ManagedGroup, &Sender, &RemoveProposal);
/// Event listener function for UpdateProposals
/// `(managed_group: &ManagedGroup, sender: &Sender, update_porposal: &UpdateProposal)`
pub type MemberUpdated = fn(&ManagedGroup, &Sender, &UpdateProposal);
/// Event listener function for application messages
/// `(managed_group: &ManagedGroup, message: &[u8], aad: &[u8])`
pub type AppMessageReceived = fn(&ManagedGroup, &[u8], &[u8]);
