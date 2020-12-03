pub mod callbacks;
pub mod config;
pub mod errors;
mod ser;

use crate::creds::{Credential, CredentialBundle};
use crate::framing::*;
use crate::group::*;
use crate::key_packages::{KeyPackage, KeyPackageBundle};
use crate::messages::{proposals::*, Welcome};
use crate::tree::index::LeafIndex;
use crate::tree::node::Node;

use std::collections::HashMap;
use std::io::{Error, Read, Write};

pub use callbacks::*;
pub use config::*;
pub use errors::{InvalidMessageError, ManagedGroupError};
use ser::*;

/// A `ManagedGroup` represents an [MlsGroup] with
/// an easier, high-level API designed to be used in production. The API exposes
/// high level functions to manage a group by adding/removing members, get the
/// current member list, etc.
///
/// The API is modeled such that it can serve as a direct interface to the
/// Delivery Service. Functions that modify the public state of the group will
/// return a `Vec<MLSMessage>` that can be sent to the Delivery
/// Service directly. Conversely, incoming messages from the Delivery Service
/// can be fed into [process_messages()](`ManagedGroup::process_messages()`).
///
/// A `ManagedGroup` has an internal queue of pending proposals that builds up
/// as new messages are processed. When creating proposals, those messages are
/// not automatically appended to this queue, instead they have to be processed
/// again through [process_messages()](`ManagedGroup::process_messages()`). This
/// allows the Delivery Service to reject them (e.g. if they reference the wrong
/// epoch).
///
/// If incoming messages or applied operations are semantically or syntactically
/// incorrect, a callback function will be called with a corresponding error
/// message and the state of the group will remain unchanged.
///
/// The application policy for the group can be enforced by implementing the
/// validator callback functions and selectively allowing/ disallowing each
/// operation (see [`ManagedGroupCallbacks`])
///
/// Changes to the group state are dispatched as events through callback
/// functions (see [`ManagedGroupCallbacks`]).
#[derive(Debug, PartialEq)]
pub struct ManagedGroup<'a> {
    // CredentialBundle used to sign messages
    credential_bundle: &'a CredentialBundle,
    // The group configuration. See `ManagedGroupCongig` for more information.
    managed_group_config: ManagedGroupConfig,
    // the internal `MlsGroup` used for lower level operations. See `MlsGroup` for more
    // information.
    group: MlsGroup,
    // A queue of incoming proposals from the DS for a given epoch. New proposals are added to the
    // queue through `process_messages()`. The queue is emptied after every epoch change.
    pending_proposals: Vec<MLSPlaintext>,
    // Own `KeyPackageBundle`s that were created for update proposals or commits. The vector is
    // emptied after every epoch change.
    own_kpbs: Vec<KeyPackageBundle>,
    // The AAD that is used for all outgoing handshake messages. The AAD can be set through
    // `set_aad()`.
    aad: Vec<u8>,
    // A flag that indicates if the current client is still a member of a group. The value is set
    // to `true` upon group creation and is set to `false` when the client gets evicted from the
    // group`.
    active: bool,
}

impl<'a> ManagedGroup<'a> {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member.
    pub fn new(
        credential_bundle: &'a CredentialBundle,
        managed_group_config: &ManagedGroupConfig,
        group_id: GroupId,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, ManagedGroupError> {
        let group = MlsGroup::new(
            &group_id.as_slice(),
            key_package_bundle.key_package().ciphersuite().name(),
            key_package_bundle,
            GroupConfig::default(),
        )?;

        Ok(ManagedGroup {
            credential_bundle,
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
        credential_bundle: &'a CredentialBundle,
        managed_group_config: &ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, WelcomeError> {
        let group = MlsGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle)?;
        Ok(ManagedGroup {
            credential_bundle,
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
        key_packages: &[KeyPackage],
    ) -> Result<(Vec<MLSMessage>, Welcome), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        // Create framed add proposals from key packages
        let mut plaintext_messages: Vec<MLSPlaintext> = key_packages
            .iter()
            .map(|key_package| {
                self.group.create_add_proposal(
                    &self.aad,
                    &self.credential_bundle,
                    key_package.clone(),
                )
            })
            .collect();

        // Include pending proposals into Commit
        let mut messages_to_commit = self.pending_proposals.clone();
        messages_to_commit.extend_from_slice(&plaintext_messages);

        // Create Commit over all proposals
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &self.credential_bundle,
            &messages_to_commit,
            false,
        )?;

        // Add the Commit message to the other pending messages
        plaintext_messages.push(commit);

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
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        let mut plaintext_messages: Vec<MLSPlaintext> = members
            .iter()
            .map(|member| {
                self.group.create_remove_proposal(
                    &self.aad,
                    &self.credential_bundle,
                    LeafIndex::from(*member),
                )
            })
            .collect();

        // Include pending proposals into Commit
        let mut messages_to_commit = self.pending_proposals.clone();
        messages_to_commit.extend_from_slice(&plaintext_messages);

        // Create Commit over all proposals
        let (commit, _, kpb_option) = self.group.create_commit(
            &self.aad,
            &self.credential_bundle,
            &messages_to_commit,
            false,
        )?;

        // Add the Commit message to the other pending messages
        plaintext_messages.push(commit);

        // It has to be a full Commit and we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        } else {
            return Err(ManagedGroupError::Unknown);
        }

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_members(
        &mut self,
        key_packages: &[KeyPackage],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        let plaintext_messages: Vec<MLSPlaintext> = key_packages
            .iter()
            .map(|key_package| {
                self.group.create_add_proposal(
                    &self.aad,
                    &self.credential_bundle,
                    key_package.clone(),
                )
            })
            .collect();

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Creates proposals to remove members from the group
    pub fn propose_remove_members(
        &mut self,
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        let plaintext_messages: Vec<MLSPlaintext> = members
            .iter()
            .map(|member| {
                self.group.create_remove_proposal(
                    &self.aad,
                    &self.credential_bundle,
                    LeafIndex::from(*member),
                )
            })
            .collect();

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Leave the group
    pub fn leave_group(&mut self) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        let remove_proposal = self.group.create_remove_proposal(
            &self.aad,
            &self.credential_bundle,
            LeafIndex::from(self.group.tree().own_node_index()),
        );

        let mls_messages = self.plaintext_to_mls_messages(vec![remove_proposal]);
        Ok(mls_messages)
    }

    /// Gets the current list of members
    pub fn members(&self) -> Vec<Credential> {
        let mut members: Vec<Credential> = vec![];
        let tree = self.group.tree();
        let leaf_count = self.group.tree().leaf_count();
        for index in 0..leaf_count.as_usize() {
            let leaf = &tree.nodes[LeafIndex::from(index)];
            if let Some(leaf_node) = leaf.key_package() {
                members.push(leaf_node.credential().clone());
            }
        }
        members
    }

    // === Process messages ===

    /// Processes any incoming messages from the DS (MLSPlaintext &
    /// MLSCiphertext) and triggers the corresponding callback functions
    pub fn process_messages(&mut self, messages: Vec<MLSMessage>) -> Result<(), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        // Iterate over all incoming messages
        for message in messages {
            // Check the type of message we received
            let (plaintext, aad_option) = match message {
                // If it is a ciphertext we decrypt it and return the plaintext by value
                MLSMessage::Ciphertext(ciphertext) => {
                    let aad = ciphertext.authenticated_data.clone();
                    match self.group.decrypt(&ciphertext) {
                        Ok(plaintext) => (plaintext, Some(aad)),
                        Err(_) => {
                            // If there is a callback for that event we should call it
                            self.invalid_message_event(InvalidMessageError::InvalidCiphertext(
                                aad.to_vec(),
                            ));
                            // Since we cannot decrypt the MLSCiphertext to a MLSPlaintext we move
                            // to the next message
                            continue;
                        }
                    }
                }
                // If it is a plaintext message we just return the reference
                MLSMessage::Plaintext(plaintext) => (plaintext, None),
            };
            // Save the current member list for validation end events
            let indexed_members = self.indexed_members();
            // See what kind of message it is
            match plaintext.content {
                MLSPlaintextContentType::Proposal(_) => {
                    // Incoming proposals are validated against the application validation
                    // policy and then appended to the internal `pending_proposal` list.
                    // TODO #133: Semantic validation of proposals
                    if self.validate_proposal(&plaintext, indexed_members) {
                        self.pending_proposals.push(plaintext);
                    } else {
                        self.invalid_message_event(InvalidMessageError::CommitWithInvalidProposals);
                    }
                }
                MLSPlaintextContentType::Commit(_) => {
                    // If all proposals were valid, we continue with applying the Commit
                    // message
                    match self.group.apply_commit(
                        plaintext,
                        self.pending_proposals.clone(),
                        &self.own_kpbs,
                    ) {
                        Ok(()) => {
                            // Since the Commit was applied without errors, we can call all
                            // corresponding callback functions for the whole proposal list
                            self.send_events(indexed_members);
                            // We don't need the pending proposals and key package bundles any
                            // longer
                            self.pending_proposals.clear();
                            self.own_kpbs.clear();
                        }
                        Err(apply_commit_error) => match apply_commit_error {
                            ApplyCommitError::SelfRemoved => {
                                // Send out events
                                self.send_events(indexed_members);
                                // The group is no longer active
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
                            &aad_option.unwrap(),
                            &indexed_members[&plaintext.sender()],
                            app_message,
                        );
                    }
                }
            }
        }
        Ok(())
    }

    // === Application messages ===

    /// Creates an application message.  
    /// Returns `ManagedGroupError::UseAfterEviction` if the member is no longer
    /// part of the group. Returns `ManagedGroupError::
    /// PendingProposalsExist` if pending proposals exist. In that case
    /// `.process_pending_proposals()` must be called first and incoming
    /// messages from the DS must be processed afterwards.
    pub fn create_message(&mut self, message: &[u8]) -> Result<MLSMessage, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        if !self.pending_proposals.is_empty() {
            return Err(ManagedGroupError::PendingProposalsExist);
        }
        let ciphertext =
            self.group
                .create_application_message(&self.aad, message, &self.credential_bundle);
        Ok(MLSMessage::Ciphertext(ciphertext))
    }

    /// Process pending proposals
    pub fn process_pending_proposals(
        &mut self,
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        // Create Commit over all pending proposals
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &self.credential_bundle,
            &self.pending_proposals,
            true,
        )?;

        // Add the Commit message to the other pending messages
        let plaintext_messages = vec![commit];

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok((mls_messages, welcome_option))
    }

    // === Export secrets ===

    /// Exports a secret from the current epoch
    pub fn export_secret(
        &self,
        label: &str,
        key_length: usize,
    ) -> Result<Vec<u8>, ManagedGroupError> {
        if self.active {
            Ok(self.group.export_secret(label, key_length)?)
        } else {
            Err(ManagedGroupError::UseAfterEviction)
        }
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

    /// Returns whether the own client is still a member of the group or if it
    /// was already evicted
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Sets a different `CredentialBundle`
    pub fn set_credential_bundle(&mut self, credential_bundle: &'a CredentialBundle) {
        self.credential_bundle = credential_bundle;
    }

    /// Returns own credential
    pub fn credential(&self) -> &Credential {
        &self.credential_bundle.credential()
    }

    /// Get group ID
    pub fn group_id(&self) -> &GroupId {
        self.group.group_id()
    }

    /// Updates the own leaf node
    pub fn self_update(
        &mut self,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        // Use provided KeyPackageBundle or create a new one
        let tree = self.group.tree();
        let key_package_bundle = match key_package_bundle_option {
            Some(kpb) => kpb,
            None => {
                let existing_key_package = tree.own_key_package();
                KeyPackageBundle::from_rekeyed_key_package(existing_key_package)
            }
        };
        drop(tree);

        // Create UpdateProposal
        let mut plaintext_messages = vec![self.group.create_update_proposal(
            &self.aad,
            &self.credential_bundle,
            key_package_bundle.key_package().clone(),
        )];

        // Include pending proposals into Commit
        let mut messages_to_commit = self.pending_proposals.clone();
        messages_to_commit.extend_from_slice(&plaintext_messages);

        // Create Commit over all proposals
        let (commit, _welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &self.credential_bundle,
            &messages_to_commit,
            false,
        )?;

        // Add the Commit message to the other pending messages
        plaintext_messages.push(commit);

        // Take the new KeyPackageBundle and save it for later
        let kpb = match kpb_option {
            Some(kpb) => kpb,
            None => return Err(ManagedGroupError::Unknown),
        };
        self.own_kpbs.push(kpb);

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Creates a proposal to update the own leaf node
    pub fn propose_self_update(
        &mut self,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction);
        }
        let tree = self.group.tree();
        let existing_key_package = tree.own_key_package();
        let key_package_bundle = match key_package_bundle_option {
            Some(kpb) => kpb,
            None => KeyPackageBundle::from_rekeyed_key_package(existing_key_package),
        };

        let plaintext_messages = vec![self.group.create_update_proposal(
            &self.aad,
            &self.credential_bundle,
            key_package_bundle.key_package().clone(),
        )];
        drop(tree);

        self.own_kpbs.push(key_package_bundle);

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages);

        Ok(mls_messages)
    }

    /// Returns a list of proposal
    pub fn pending_proposals(&self) -> &[MLSPlaintext] {
        &self.pending_proposals
    }

    // === Load & save ===

    /// Loads the state from persisted state
    pub fn load<R: Read>(
        reader: R,
        credential_bundle: &'a CredentialBundle,
        callbacks: ManagedGroupCallbacks,
    ) -> Result<ManagedGroup<'a>, Error> {
        let serialized_managed_group: SerializedManagedGroup = serde_json::from_reader(reader)?;
        Ok(serialized_managed_group.into_managed_group(credential_bundle, callbacks))
    }

    /// Persists the state
    pub fn save<W: Write>(&self, writer: &mut W) -> Result<(), Error> {
        let serialized_managed_group = serde_json::to_string_pretty(self)?;
        writer.write_all(&serialized_managed_group.into_bytes())
    }

    // === Extensions ===

    /// Export the Ratchet Tree
    pub fn export_ratchet_tree(&self) -> Vec<Option<Node>> {
        self.group.tree().public_key_tree_copy()
    }
}

// Private methods of ManagedGroup
impl<'a> ManagedGroup<'a> {
    /// Converts MLSPlaintext to MLSMessage. Depending on whether handshake
    /// message should be encrypted, MLSPlaintext messages are encrypted to
    /// MLSCiphertext first.
    fn plaintext_to_mls_messages(
        &mut self,
        plaintext_messages: Vec<MLSPlaintext>,
    ) -> Vec<MLSMessage> {
        plaintext_messages
            .into_iter()
            .map(
                |plaintext| match self.configuration().handshake_message_format {
                    HandshakeMessageFormat::Plaintext => MLSMessage::Plaintext(plaintext),
                    HandshakeMessageFormat::Ciphertext => {
                        let ciphertext = self.group.encrypt(plaintext);
                        MLSMessage::Ciphertext(ciphertext)
                    }
                },
            )
            .collect()
    }

    /// Validate all pending proposals. The function returns `true` only if all
    /// proposals are valid.
    fn validate_proposal(
        &self,
        framed_proposal: &MLSPlaintext,
        indexed_members: HashMap<LeafIndex, Credential>,
    ) -> bool {
        let sender = &indexed_members[&framed_proposal.sender()];
        match framed_proposal.content {
            MLSPlaintextContentType::Proposal(ref proposal) => match proposal {
                // Validate add proposals
                Proposal::Add(add_proposal) => {
                    if let Some(validate_add) = self.managed_group_config.callbacks.validate_add {
                        if !validate_add(&self, sender, add_proposal.key_package.credential()) {
                            return false;
                        }
                    }
                }
                // Validate remove proposals
                Proposal::Remove(remove_proposal) => {
                    if let Some(validate_remove) =
                        self.managed_group_config.callbacks.validate_remove
                    {
                        if !validate_remove(
                            &self,
                            sender,
                            &indexed_members[&LeafIndex::from(remove_proposal.removed)],
                        ) {
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
    fn send_events(&self, indexed_members: HashMap<LeafIndex, Credential>) {
        for framed_proposal in &self.pending_proposals {
            let sender = &indexed_members[&framed_proposal.sender()];
            match framed_proposal.content {
                MLSPlaintextContentType::Proposal(ref proposal) => match proposal {
                    // Add proposals
                    Proposal::Add(add_proposal) => {
                        if let Some(member_added) = self.managed_group_config.callbacks.member_added
                        {
                            member_added(
                                &self,
                                &self.aad,
                                sender,
                                add_proposal.key_package.credential(),
                            )
                        }
                    }
                    // Update proposals
                    Proposal::Update(update_proposal) => {
                        if let Some(member_updated) =
                            self.managed_group_config.callbacks.member_updated
                        {
                            member_updated(
                                &self,
                                &self.aad,
                                update_proposal.key_package.credential(),
                            )
                        }
                    }
                    // Remove proposals
                    Proposal::Remove(remove_proposal) => {
                        let removal = Removal::new(
                            self.credential_bundle.credential(),
                            sender,
                            &indexed_members[&LeafIndex::from(remove_proposal.removed)],
                        );

                        if let Some(member_removed) =
                            self.managed_group_config.callbacks.member_removed
                        {
                            member_removed(&self, &self.aad, &removal)
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

    /// Return a list (LeafIndex, Credential)
    fn indexed_members(&self) -> HashMap<LeafIndex, Credential> {
        let mut indexed_members = HashMap::new();
        let tree = self.group.tree();
        let leaf_count = self.group.tree().leaf_count();
        for index in 0..leaf_count.as_usize() {
            let leaf_index = LeafIndex::from(index);
            let leaf = &tree.nodes[leaf_index];
            if let Some(leaf_node) = leaf.key_package() {
                indexed_members.insert(leaf_index, leaf_node.credential().clone());
            }
        }
        indexed_members
    }
}

/// Unified message type
#[derive(PartialEq, Debug, Clone)]
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
