pub mod callbacks;
pub mod config;
pub mod errors;
pub mod events;
mod resumption;
mod ser;
#[cfg(test)]
mod test_managed_group;

use crate::{
    credentials::Credential,
    error::ErrorString,
    framing::*,
    group::*,
    key_packages::{KeyPackage, KeyPackageBundle},
    key_store::KeyStore,
    messages::{proposals::*, Welcome},
    schedule::ResumptionSecret,
    tree::{index::LeafIndex, node::Node},
};

use std::collections::HashMap;
use std::io::{Error, Read, Write};

pub use callbacks::*;
pub use config::*;
pub use errors::{
    EmptyInputError, InvalidMessageError, ManagedGroupError, PendingProposalsError,
    UseAfterEviction,
};
pub use events::*;
pub(crate) use resumption::ResumptionSecretStore;
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
/// incorrect, an error event will be returned with a corresponding error
/// message and the state of the group will remain unchanged.
///
/// The application policy for the group can be enforced by implementing the
/// validator callback functions and selectively allowing/ disallowing each
/// operation (see [`ManagedGroupCallbacks`])
///
/// Changes to the group state are dispatched as events through callback
/// functions (see [`ManagedGroupCallbacks`]).
#[derive(Debug)]
pub struct ManagedGroup {
    // The group configuration. See `ManagedGroupCongig` for more information.
    managed_group_config: ManagedGroupConfig,
    // the internal `MlsGroup` used for lower level operations. See `MlsGroup` for more
    // information.
    group: MlsGroup,
    // A queue of incoming proposals from the DS for a given epoch. New proposals are added to the
    // queue through `process_messages()`. The queue is emptied after every epoch change.
    pending_proposals: Vec<MlsPlaintext>,
    // Own `KeyPackageBundle`s that were created for update proposals or commits. The vector is
    // emptied after every epoch change.
    own_kpbs: Vec<KeyPackageBundle>,
    // The AAD that is used for all outgoing handshake messages. The AAD can be set through
    // `set_aad()`.
    aad: Vec<u8>,
    // Resumption secret store. This is where the resumption secrets are kept in a rollover list.
    resumption_secret_store: ResumptionSecretStore,
    // A flag that indicates if the current client is still a member of a group. The value is set
    // to `true` upon group creation and is set to `false` when the client gets evicted from the
    // group`.
    active: bool,
}

impl ManagedGroup {
    // === Group creation ===

    /// Creates a new group from scratch with only the creator as a member. This
    /// function removes the `KeyPackageBundle` corresponding to the
    /// `key_package_hash` from the `key_store`. Throws an error if no
    /// `KeyPackageBundle` can be found.
    pub fn new(
        key_store: &KeyStore,
        managed_group_config: &ManagedGroupConfig,
        group_id: GroupId,
        key_package_hash: &[u8],
    ) -> Result<Self, ManagedGroupError> {
        // TODO #141
        let key_package_bundle = key_store
            .take_key_package_bundle(key_package_hash)
            .ok_or(ManagedGroupError::NoMatchingKeyPackageBundle)?;
        let group = MlsGroup::new(
            &group_id.as_slice(),
            key_package_bundle.key_package().ciphersuite_name(),
            key_package_bundle,
            GroupConfig::default(),
            None, /* Initial PSK */
            None, /* MLS version */
        )?;

        let resumption_secret_store =
            ResumptionSecretStore::new(managed_group_config.number_of_resumption_secrets);

        let managed_group = ManagedGroup {
            managed_group_config: managed_group_config.clone(),
            group,
            pending_proposals: vec![],
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            active: true,
        };

        // Since the state of the group was changed, call the auto-save function
        managed_group.auto_save();

        Ok(managed_group)
    }

    /// Creates a new group from a `Welcome` message
    pub fn new_from_welcome(
        key_store: &KeyStore,
        managed_group_config: &ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
    ) -> Result<Self, ManagedGroupError> {
        let resumption_secret_store =
            ResumptionSecretStore::new(managed_group_config.number_of_resumption_secrets);
        let key_package_bundle = welcome
            .secrets()
            .iter()
            .find_map(|egs| key_store.take_key_package_bundle(&egs.key_package_hash))
            .ok_or(ManagedGroupError::NoMatchingKeyPackageBundle)?;
        // TODO #141
        let group = MlsGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle, None)?;

        let managed_group = ManagedGroup {
            managed_group_config: managed_group_config.clone(),
            group,
            pending_proposals: vec![],
            own_kpbs: vec![],
            aad: vec![],
            resumption_secret_store,
            active: true,
        };

        // Since the state of the group was changed, call the auto-save function
        managed_group.auto_save();

        Ok(managed_group)
    }

    // === Membership management ===

    /// Adds members to the group
    ///
    /// New members are added by providing a `KeyPackage` for each member.
    ///
    /// The `include_path` flag controls if a Path is included in the Commit.
    ///
    /// If successful, it returns a `Vec` of
    /// [`MLSMessage`](crate::prelude::MLSMessage) and a
    /// [`Welcome`](crate::prelude::Welcome) message.
    pub fn add_members(
        &mut self,
        key_store: &KeyStore,
        key_packages: &[KeyPackage],
        include_path: bool,
    ) -> Result<(Vec<MlsMessage>, Welcome), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        if key_packages.is_empty() {
            return Err(ManagedGroupError::EmptyInput(EmptyInputError::AddMembers));
        }

        // Create add proposals by value from key packages
        let proposals = key_packages
            .iter()
            .map(|key_package| {
                Proposal::Add(AddProposal {
                    key_package: key_package.clone(),
                })
            })
            .collect::<Vec<Proposal>>();
        let proposals_by_value = &proposals.iter().collect::<Vec<&Proposal>>();

        // Include pending proposals
        let proposals_by_reference = &self
            .pending_proposals
            .iter()
            .collect::<Vec<&MlsPlaintext>>();

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #141
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &credential_bundle,
            proposals_by_reference,
            proposals_by_value,
            include_path,
            None,
        )?;

        let welcome = match welcome_option {
            Some(welcome) => welcome,
            None => {
                return Err(ManagedGroupError::LibraryError(
                    "No secrets to generate commit message.".into(),
                ))
            }
        };

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(vec![commit])?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_messages, welcome))
    }

    /// Removes members from the group
    ///
    /// Members are removed by providing the index of their leaf in the tree.
    ///
    /// If successful, it returns a `Vec` of
    /// [`MLSMessage`](crate::prelude::MLSMessage) and an optional
    /// [`Welcome`](crate::prelude::Welcome) message if there were add proposals
    /// in the queue of pending proposals.
    pub fn remove_members(
        &mut self,
        key_store: &KeyStore,
        members: &[usize],
    ) -> Result<(Vec<MlsMessage>, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        if members.is_empty() {
            return Err(ManagedGroupError::EmptyInput(
                EmptyInputError::RemoveMembers,
            ));
        }

        // Create add proposals by value
        let proposals = members
            .iter()
            .map(|member| {
                Proposal::Remove(RemoveProposal {
                    removed: *member as u32,
                })
            })
            .collect::<Vec<Proposal>>();
        let proposals_by_value = &proposals.iter().collect::<Vec<&Proposal>>();

        // Include pending proposals
        let proposals_by_reference = &self
            .pending_proposals
            .iter()
            .collect::<Vec<&MlsPlaintext>>();

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #141
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &credential_bundle,
            proposals_by_reference,
            proposals_by_value,
            false,
            None,
        )?;

        // It has to be a full Commit and we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        } else {
            return Err(ManagedGroupError::LibraryError(
                "We didn't get a key package for a full commit.".into(),
            ));
        }

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(vec![commit])?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_messages, welcome_option))
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_members(
        &mut self,
        key_store: &KeyStore,
        key_packages: &[KeyPackage],
    ) -> Result<Vec<MlsMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let plaintext_messages: Vec<MlsPlaintext> = {
            let mut messages = vec![];
            for key_package in key_packages.iter() {
                let add_proposal = self.group.create_add_proposal(
                    &self.aad,
                    &credential_bundle,
                    key_package.clone(),
                )?;
                messages.push(add_proposal);
            }
            messages
        };

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(mls_messages)
    }

    /// Creates proposals to remove members from the group
    pub fn propose_remove_members(
        &mut self,
        key_store: &KeyStore,
        members: &[usize],
    ) -> Result<Vec<MlsMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let plaintext_messages: Vec<MlsPlaintext> = {
            let mut messages = vec![];
            for member in members.iter() {
                let remove_proposal = self.group.create_remove_proposal(
                    &self.aad,
                    &credential_bundle,
                    LeafIndex::from(*member),
                )?;
                messages.push(remove_proposal);
            }
            messages
        };

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(mls_messages)
    }

    /// Leave the group
    pub fn leave_group(
        &mut self,
        key_store: &KeyStore,
    ) -> Result<Vec<MlsMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let remove_proposal = self.group.create_remove_proposal(
            &self.aad,
            &credential_bundle,
            self.group.tree().own_node_index(),
        )?;

        self.plaintext_to_mls_messages(vec![remove_proposal])
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

    /// Processes any incoming messages from the DS (MlsPlaintext &
    /// MlsCiphertext) and triggers the corresponding callback functions.
    /// Return a list of `GroupEvent` that contain the individual events that
    /// occurred while processing messages.
    pub fn process_messages(
        &mut self,
        messages: Vec<MlsMessage>,
    ) -> Result<Vec<GroupEvent>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        let mut events = Vec::new();
        // Iterate over all incoming messages
        for message in messages {
            // Check the type of message we received
            let (plaintext, aad_option) = match message {
                // If it is a ciphertext we decrypt it and return the plaintext message
                MlsMessage::Ciphertext(ciphertext) => {
                    let aad = ciphertext.authenticated_data.clone();
                    match self.group.decrypt(&ciphertext) {
                        Ok(plaintext) => (plaintext, Some(aad)),
                        Err(_) => {
                            events.push(GroupEvent::InvalidMessage(InvalidMessageEvent::new(
                                InvalidMessageError::InvalidCiphertext(aad.into()),
                            )));
                            // Since we cannot decrypt the MlsCiphertext to a MlsPlaintext we move
                            // to the next message
                            continue;
                        }
                    }
                }
                // If it is a plaintext message we just return it
                MlsMessage::Plaintext(plaintext) => {
                    // Verify signature & membership tag
                    // TODO #106: Support external senders
                    if plaintext.is_proposal()
                        && plaintext.sender.is_member()
                        && self.group.verify_membership_tag(&plaintext).is_err()
                    {
                        events.push(GroupEvent::InvalidMessage(InvalidMessageEvent::new(
                            InvalidMessageError::MembershipTagMismatch,
                        )));
                        // Since the membership tag verification failed, we skip the message
                        // and go to the next one
                        continue;
                    }
                    (plaintext, None)
                }
            };
            // Save the current member list for validation end events
            let indexed_members = self.indexed_members();
            // See what kind of message it is
            match plaintext.content {
                MlsPlaintextContentType::Proposal(_) => {
                    // Incoming proposals are validated against the application validation
                    // policy and then appended to the internal `pending_proposal` list.
                    // TODO #133: Semantic validation of proposals
                    if self.validate_proposal(
                        plaintext.content.to_proposal(),
                        &plaintext.sender.sender,
                        &indexed_members,
                    ) {
                        self.pending_proposals.push(plaintext);
                    } else {
                        // The proposal was invalid
                        events.push(GroupEvent::InvalidMessage(InvalidMessageEvent::new(
                            InvalidMessageError::CommitWithInvalidProposals(
                                "Invalid proposal".into(),
                            ),
                        )));
                    }
                }
                MlsPlaintextContentType::Commit(ref commit) => {
                    // Validate inline proposals
                    if !self.validate_inline_proposals(
                        &commit.proposals,
                        &plaintext.sender.sender,
                        &indexed_members,
                    ) {
                        // If not all proposals are valid we issue an error event
                        events.push(GroupEvent::InvalidMessage(InvalidMessageEvent::new(
                            InvalidMessageError::CommitWithInvalidProposals(
                                "Not all proposals are valid".into(),
                            ),
                        )));
                        // And move on to the next message
                        continue;
                    }
                    // If all proposals were valid, we continue with applying the Commit
                    // message
                    let proposals = &self
                        .pending_proposals
                        .iter()
                        .collect::<Vec<&MlsPlaintext>>();
                    // TODO #141
                    match self
                        .group
                        .apply_commit(&plaintext, proposals, &self.own_kpbs, None)
                    {
                        Ok(()) => {
                            // Since the Commit was applied without errors, we can collect
                            // all proposals from the Commit and generate events
                            events.append(&mut self.prepare_events(
                                self.ciphersuite(),
                                &commit.proposals,
                                plaintext.sender.sender,
                                &indexed_members,
                            ));

                            // If a Commit has an update path, it is additionally to be treated
                            // like a commited UpdateProposal.
                            if commit.has_path() {
                                events.push(GroupEvent::MemberUpdated(MemberUpdatedEvent::new(
                                    aad_option.unwrap_or_default(),
                                    indexed_members[&plaintext.sender.sender].clone(),
                                )));
                            }

                            // Extract and store the resumption secret for the current epoch
                            let resumption_secret = self.group.epoch_secrets().resumption_secret();
                            self.resumption_secret_store
                                .add(self.group.context().epoch(), resumption_secret.clone());
                            // We don't need the pending proposals and key package bundles any
                            // longer
                            self.pending_proposals.clear();
                            self.own_kpbs.clear();
                        }
                        Err(apply_commit_error) => match apply_commit_error {
                            GroupError::ApplyCommitError(ApplyCommitError::SelfRemoved) => {
                                // Prepare events
                                events.append(&mut self.prepare_events(
                                    self.ciphersuite(),
                                    &commit.proposals,
                                    plaintext.sender.sender,
                                    &indexed_members,
                                ));
                                // The group is no longer active
                                self.active = false;
                            }
                            GroupError::ApplyCommitError(e) => {
                                events.push(GroupEvent::InvalidMessage(InvalidMessageEvent::new(
                                    InvalidMessageError::CommitError(e),
                                )));
                            }
                            _ => {
                                let error_string =
                                    "apply_commit() did not return an ApplyCommitError."
                                        .to_string();
                                events.push(GroupEvent::Error(ErrorEvent::new(
                                    ManagedGroupError::LibraryError(ErrorString::from(
                                        error_string,
                                    )),
                                )));
                            }
                        },
                    }
                }
                MlsPlaintextContentType::Application(ref app_message) => {
                    // Save the application message as an event
                    events.push(GroupEvent::ApplicationMessage(
                        ApplicationMessageEvent::new(
                            aad_option.unwrap(),
                            indexed_members[&plaintext.sender()].clone(),
                            app_message.to_vec(),
                        ),
                    ));
                }
            }
        }

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(events)
    }

    // === Application messages ===

    /// Creates an application message.
    /// Returns `ManagedGroupError::UseAfterEviction(UseAfterEviction::Error)`
    /// if the member is no longer part of the group.
    /// Returns `ManagedGroupError::PendingProposalsExist` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message(
        &mut self,
        key_store: &KeyStore,
        message: &[u8],
    ) -> Result<MlsMessage, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        if !self.pending_proposals.is_empty() {
            return Err(ManagedGroupError::PendingProposalsExist(
                PendingProposalsError::Exists,
            ));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let ciphertext = self.group.create_application_message(
            &self.aad,
            message,
            &credential_bundle,
            self.configuration().padding_size(),
        )?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(MlsMessage::Ciphertext(ciphertext))
    }

    /// Process pending proposals
    pub fn process_pending_proposals(
        &mut self,
        key_store: &KeyStore,
    ) -> Result<(Vec<MlsMessage>, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        // Include pending proposals into Commit
        let messages_to_commit: Vec<&MlsPlaintext> = self.pending_proposals.iter().collect();

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all pending proposals
        // TODO #141
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &credential_bundle,
            &messages_to_commit,
            &[],
            true,
            None,
        )?;

        // Add the Commit message to the other pending messages
        let plaintext_messages = vec![commit];

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_messages, welcome_option))
    }

    // === Export secrets ===

    /// Exports a secret from the current epoch
    pub fn export_secret(
        &self,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, ManagedGroupError> {
        if self.active {
            Ok(self.group.export_secret(label, context, key_length)?)
        } else {
            Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error))
        }
    }

    /// Returns the authentication secret
    pub fn authentication_secret(&self) -> Vec<u8> {
        self.group.authentication_secret()
    }

    /// Returns a resumption secret for a given epoch. If no resumption secret
    /// is available `None` is returned.
    pub fn get_resumption_secret(&self, epoch: GroupEpoch) -> Option<&ResumptionSecret> {
        self.resumption_secret_store.get(epoch)
    }

    // === Configuration ===

    /// Gets the configuration
    pub fn configuration(&self) -> &ManagedGroupConfig {
        &self.managed_group_config
    }

    /// Sets the configuration
    pub fn set_configuration(&mut self, managed_group_config: &ManagedGroupConfig) {
        self.managed_group_config = managed_group_config.clone();

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();
    }

    /// Gets the AAD used in the framing
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Sets the AAD used in the framing
    pub fn set_aad(&mut self, aad: &[u8]) {
        self.aad = aad.to_vec();

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();
    }

    // === Advanced functions ===

    /// Returns the group's ciphersuite
    pub fn ciphersuite(&self) -> &Ciphersuite {
        self.group.ciphersuite()
    }

    /// Returns whether the own client is still a member of the group or if it
    /// was already evicted
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Returns own credential. If the group is inactive, it returns a
    /// `UseAfterEviction` error. This function currently returns a full
    /// `Credential` rather than just a reference. This issue is tracked in
    /// issue #387.
    pub fn credential(&self) -> Result<Credential, ManagedGroupError> {
        if !self.is_active() {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        let tree = self.group.tree();
        Ok(tree.own_key_package().credential().clone())
    }

    /// Get group ID
    pub fn group_id(&self) -> &GroupId {
        self.group.group_id()
    }

    /// Updates the own leaf node
    ///
    /// A [`KeyPackageBundle`](crate::prelude::KeyPackageBundle) can optionally
    /// be provided. If not, a new one will be created on the fly.
    ///
    /// If successful, it returns a `Vec` of
    /// [`MLSMessage`](crate::prelude::MLSMessage) and an optional
    /// [`Welcome`](crate::prelude::Welcome) message if there were add proposals
    /// in the queue of pending proposals.
    pub fn self_update(
        &mut self,
        key_store: &KeyStore,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<(Vec<MlsMessage>, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // If a KeyPackageBundle was provided, create an UpdateProposal
        let mut plaintext_messages = if let Some(key_package_bundle) = key_package_bundle_option {
            let update_proposal = self.group.create_update_proposal(
                &self.aad,
                &credential_bundle,
                key_package_bundle.key_package().clone(),
            )?;
            self.own_kpbs.push(key_package_bundle);
            vec![update_proposal]
        } else {
            vec![]
        };

        // Include pending proposals into Commit
        let messages_to_commit: Vec<&MlsPlaintext> = self
            .pending_proposals
            .iter()
            .chain(plaintext_messages.iter())
            .collect();

        // Create Commit over all proposals
        // TODO #141
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &credential_bundle,
            &messages_to_commit,
            &[],
            true, /* force_self_update */
            None,
        )?;

        // Add the Commit message to the other pending messages
        plaintext_messages.push(commit);

        // Take the new KeyPackageBundle and save it for later
        let kpb = match kpb_option {
            Some(kpb) => kpb,
            None => {
                return Err(ManagedGroupError::LibraryError(
                    "We didn't get a key package for a full commit on self update.".into(),
                ))
            }
        };
        self.own_kpbs.push(kpb);

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_messages, welcome_option))
    }

    /// Creates a proposal to update the own leaf node
    pub fn propose_self_update(
        &mut self,
        key_store: &KeyStore,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<Vec<MlsMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let tree = self.group.tree();
        let existing_key_package = tree.own_key_package();
        let key_package_bundle = match key_package_bundle_option {
            Some(kpb) => kpb,
            None => {
                let mut key_package_bundle =
                    KeyPackageBundle::from_rekeyed_key_package(existing_key_package);
                key_package_bundle.sign(&credential_bundle);
                key_package_bundle
            }
        };

        let plaintext_messages = vec![self.group.create_update_proposal(
            &self.aad,
            &credential_bundle,
            key_package_bundle.key_package().clone(),
        )?];
        drop(tree);

        self.own_kpbs.push(key_package_bundle);

        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(mls_messages)
    }

    /// Returns a list of proposal
    pub fn pending_proposals(&self) -> &[MlsPlaintext] {
        &self.pending_proposals
    }

    // === Load & save ===

    /// Loads the state from persisted state
    pub fn load<R: Read>(
        reader: R,
        callbacks: &ManagedGroupCallbacks,
    ) -> Result<ManagedGroup, Error> {
        let serialized_managed_group: SerializedManagedGroup = serde_json::from_reader(reader)?;
        Ok(serialized_managed_group.into_managed_group(callbacks))
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

    #[cfg(any(feature = "expose-test-vectors", test))]
    pub fn export_path_secrets(&self) -> Vec<Secret> {
        self.group.tree().private_tree().path_secrets().to_vec()
    }

    #[cfg(any(feature = "expose-test-vectors", test))]
    pub fn export_group_context(&self) -> &GroupContext {
        self.group.context()
    }

    #[cfg(any(feature = "expose-test-vectors", test))]
    pub fn tree_hash(&self) -> Vec<u8> {
        self.group.tree().tree_hash()
    }

    #[cfg(any(feature = "expose-test-vectors", test))]
    pub fn print_tree(&self, message: &str) {
        _print_tree(&self.group.tree(), message)
    }
}

// Private methods of ManagedGroup
impl ManagedGroup {
    /// Converts MlsPlaintext to MLSMessage. Depending on whether handshake
    /// message should be encrypted, MlsPlaintext messages are encrypted to
    /// MlsCiphertext first.
    fn plaintext_to_mls_messages(
        &mut self,
        mut plaintext_messages: Vec<MlsPlaintext>,
    ) -> Result<Vec<MlsMessage>, ManagedGroupError> {
        let mut out = Vec::with_capacity(plaintext_messages.len());
        for plaintext in plaintext_messages.drain(..) {
            let msg = match self.configuration().handshake_message_format {
                HandshakeMessageFormat::Plaintext => MlsMessage::Plaintext(plaintext),
                HandshakeMessageFormat::Ciphertext => {
                    let ciphertext = self
                        .group
                        .encrypt(plaintext, self.configuration().padding_size())?;
                    MlsMessage::Ciphertext(ciphertext)
                }
            };
            out.push(msg);
        }
        Ok(out)
    }

    /// Validate all pending proposals. The function returns `true` only if all
    /// proposals are valid.
    fn validate_proposal(
        &self,
        proposal: &Proposal,
        sender: &LeafIndex,
        indexed_members: &HashMap<LeafIndex, Credential>,
    ) -> bool {
        let sender = &indexed_members[sender];
        match proposal {
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
                if let Some(validate_remove) = self.managed_group_config.callbacks.validate_remove {
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
            Proposal::PreSharedKey(_) => {}
            Proposal::ReInit(_) => {}
        }
        true
    }

    /// Validates the inline proposals from a Commit message
    fn validate_inline_proposals(
        &self,
        proposals: &[ProposalOrRef],
        sender: &LeafIndex,
        indexed_members: &HashMap<LeafIndex, Credential>,
    ) -> bool {
        for proposal_or_ref in proposals {
            match proposal_or_ref {
                ProposalOrRef::Proposal(proposal) => {
                    if !self.validate_proposal(proposal, sender, indexed_members) {
                        return false;
                    }
                }
                ProposalOrRef::Reference(_) => {}
            }
        }
        true
    }

    /// Prepare the corresponding events for the proposals covered by the
    /// Commit
    fn prepare_events(
        &self,
        ciphersuite: &Ciphersuite,
        proposals: &[ProposalOrRef],
        sender: LeafIndex,
        indexed_members: &HashMap<LeafIndex, Credential>,
    ) -> Vec<GroupEvent> {
        let mut events = Vec::new();
        // We want to collect the events in the order specified by the committer.
        // We convert the pending proposals to a list of references
        let pending_proposals_list = self
            .pending_proposals
            .iter()
            .collect::<Vec<&MlsPlaintext>>();
        // Build a proposal queue for easier searching
        let pending_proposals_queue =
            ProposalQueue::from_proposals_by_reference(ciphersuite, &pending_proposals_list);
        for proposal_or_ref in proposals {
            match proposal_or_ref {
                ProposalOrRef::Proposal(proposal) => {
                    events.push(self.prepare_proposal_event(proposal, sender, indexed_members));
                }
                ProposalOrRef::Reference(proposal_reference) => {
                    if let Some(queued_proposal) = pending_proposals_queue.get(proposal_reference) {
                        events.push(self.prepare_proposal_event(
                            queued_proposal.proposal(),
                            queued_proposal.sender().to_leaf_index(),
                            indexed_members,
                        ));
                    }
                }
            }
        }
        events
    }

    /// Prepare the corresponding events for the pending proposal list.
    fn prepare_proposal_event(
        &self,
        proposal: &Proposal,
        sender: LeafIndex,
        indexed_members: &HashMap<LeafIndex, Credential>,
    ) -> GroupEvent {
        let sender_credential = &indexed_members[&sender];
        match proposal {
            // Add proposals
            Proposal::Add(add_proposal) => GroupEvent::MemberAdded(MemberAddedEvent::new(
                self.aad.to_vec(),
                sender_credential.clone(),
                add_proposal.key_package.credential().clone(),
            )),
            // Update proposals
            Proposal::Update(update_proposal) => {
                GroupEvent::MemberUpdated(MemberUpdatedEvent::new(
                    self.aad.to_vec(),
                    update_proposal.key_package.credential().clone(),
                ))
            }
            // Remove proposals
            Proposal::Remove(remove_proposal) => {
                let removal = Removal::new(
                    indexed_members[&self.group.tree().own_node_index()].clone(),
                    sender_credential.clone(),
                    indexed_members[&LeafIndex::from(remove_proposal.removed)].clone(),
                );

                GroupEvent::MemberRemoved(MemberRemovedEvent::new(self.aad.to_vec(), removal))
            }
            // PSK proposals
            Proposal::PreSharedKey(psk_proposal) => {
                let psk_id = psk_proposal.psk.clone();

                GroupEvent::PskReceived(PskReceivedEvent::new(self.aad.to_vec(), psk_id))
            }
            // ReInit proposals
            Proposal::ReInit(reinit_proposal) => {
                GroupEvent::ReInit(ReInitEvent::new(self.aad.to_vec(), reinit_proposal.clone()))
            }
        }
    }

    /// Auto-save function
    fn auto_save(&self) {
        if let Some(auto_save) = self.managed_group_config.callbacks.auto_save {
            auto_save(&self);
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
pub enum MlsMessage {
    /// An OpenMLS `MlsPlaintext`.
    Plaintext(MlsPlaintext),

    /// An OpenMLS `MlsCiphertext`.
    Ciphertext(MlsCiphertext),
}

impl From<MlsPlaintext> for MlsMessage {
    fn from(mls_plaintext: MlsPlaintext) -> Self {
        MlsMessage::Plaintext(mls_plaintext)
    }
}

impl From<MlsCiphertext> for MlsMessage {
    fn from(mls_ciphertext: MlsCiphertext) -> Self {
        MlsMessage::Ciphertext(mls_ciphertext)
    }
}

impl MlsMessage {
    /// Get the group ID as plain byte vector.
    pub fn group_id(&self) -> Vec<u8> {
        match self {
            MlsMessage::Ciphertext(m) => m.group_id.as_slice(),
            MlsMessage::Plaintext(m) => m.group_id().as_slice(),
        }
    }

    /// Get the epoch as plain u64.
    pub fn epoch(&self) -> u64 {
        match self {
            MlsMessage::Ciphertext(m) => m.epoch.0,
            MlsMessage::Plaintext(m) => m.epoch().0,
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        match self {
            MlsMessage::Ciphertext(m) => m.is_handshake_message(),
            MlsMessage::Plaintext(m) => m.is_handshake_message(),
        }
    }
}
