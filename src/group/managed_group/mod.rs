pub mod callbacks;
pub mod config;
pub mod errors;
mod ser;
#[cfg(test)]
mod test_managed_group;

use crate::framing::*;
use crate::key_packages::{KeyPackage, KeyPackageBundle};
use crate::messages::{proposals::*, Welcome};
use crate::tree::index::LeafIndex;
use crate::tree::node::Node;
use crate::{
    credentials::Credential,
    key_store::{KeyStore, KeyStoreError},
};
use crate::{credentials::CredentialBundle, group::*};

use std::{cell::Ref, collections::HashMap};
use std::{
    cell::RefCell,
    io::{Error, Read, Write},
};

pub use callbacks::*;
pub use config::*;
pub use errors::{
    EmptyInputError, InvalidMessageError, ManagedGroupError, PendingProposalsError,
    UseAfterEviction,
};
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
#[derive(Debug)]
pub struct ManagedGroup<'a> {
    // Reference to the KeyStore to obtain private key material.
    key_store: &'a KeyStore,
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
        key_store: &'a KeyStore,
        managed_group_config: &ManagedGroupConfig,
        group_id: GroupId,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, ManagedGroupError> {
        let group = MlsGroup::new(
            &group_id.as_slice(),
            key_package_bundle.key_package().ciphersuite_name(),
            key_package_bundle,
            GroupConfig::default(),
        )?;

        let managed_group = ManagedGroup {
            key_store,
            managed_group_config: managed_group_config.clone(),
            group,
            pending_proposals: vec![],
            own_kpbs: vec![],
            aad: vec![],
            active: true,
        };

        // Since the state of the group was changed, call the auto-save function
        managed_group.auto_save();

        Ok(managed_group)
    }

    /// Creates a new group from a `Welcome` message
    pub fn new_from_welcome(
        key_store: &'a KeyStore,
        managed_group_config: &ManagedGroupConfig,
        welcome: Welcome,
        ratchet_tree: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
    ) -> Result<Self, GroupError> {
        let group = MlsGroup::new_from_welcome(welcome, ratchet_tree, key_package_bundle)?;

        let managed_group = ManagedGroup {
            key_store,
            managed_group_config: managed_group_config.clone(),
            group,
            pending_proposals: vec![],
            own_kpbs: vec![],
            aad: vec![],
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
    /// If successful, it returns a `Vec` of
    /// [`MLSMessage`](crate::prelude::MLSMessage) and a
    /// [`Welcome`](crate::prelude::Welcome) message.
    pub fn add_members(
        &mut self,
        key_packages: &[KeyPackage],
    ) -> Result<(Vec<MLSMessage>, Welcome), ManagedGroupError> {
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
            .collect::<Vec<&MLSPlaintext>>();

        // Create Commit over all proposals
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &self.credential_bundle().unwrap().credential_bundle(),
            proposals_by_reference,
            proposals_by_value,
            false,
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

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
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
        members: &[usize],
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ManagedGroupError> {
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
            .collect::<Vec<&MLSPlaintext>>();

        let credential_bundle = &self.credential_bundle()?;

        // Create Commit over all proposals
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            credential_bundle.credential_bundle(),
            proposals_by_reference,
            proposals_by_value,
            false,
        )?;

        // It has to be a full Commit and we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        } else {
            return Err(ManagedGroupError::LibraryError(
                "We didn't get a key package for a full commit.".into(),
            ));
        }

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(vec![commit])?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_messages, welcome_option))
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_members(
        &mut self,
        key_packages: &[KeyPackage],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential_bundle = &self.credential_bundle()?;

        let plaintext_messages: Vec<MLSPlaintext> = {
            let mut messages = vec![];
            for key_package in key_packages.iter() {
                let add_proposal = self.group.create_add_proposal(
                    &self.aad,
                    credential_bundle.credential_bundle(),
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
        members: &[usize],
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential_bundle = &self.credential_bundle()?;

        let plaintext_messages: Vec<MLSPlaintext> = {
            let mut messages = vec![];
            for member in members.iter() {
                let remove_proposal = self.group.create_remove_proposal(
                    &self.aad,
                    credential_bundle.credential_bundle(),
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
    pub fn leave_group(&mut self) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential_bundle = &self.credential_bundle()?;

        let remove_proposal = self.group.create_remove_proposal(
            &self.aad,
            credential_bundle.credential_bundle(),
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

    /// Processes any incoming messages from the DS (MLSPlaintext &
    /// MLSCiphertext) and triggers the corresponding callback functions
    pub fn process_messages(&mut self, messages: Vec<MLSMessage>) -> Result<(), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        // Iterate over all incoming messages
        for message in messages {
            // Check the type of message we received
            let (plaintext, aad_option) = match message {
                // If it is a ciphertext we decrypt it and return the plaintext message
                MLSMessage::Ciphertext(ciphertext) => {
                    let aad = ciphertext.authenticated_data.clone();
                    match self.group.decrypt(&ciphertext) {
                        Ok(plaintext) => (plaintext, Some(aad)),
                        Err(_) => {
                            // If there is a callback for that event we should call it
                            self.invalid_message_event(InvalidMessageError::InvalidCiphertext(
                                aad.into(),
                            ));
                            // Since we cannot decrypt the MLSCiphertext to a MLSPlaintext we move
                            // to the next message
                            continue;
                        }
                    }
                }
                // If it is a plaintext message we just return it
                MLSMessage::Plaintext(plaintext) => {
                    // Verify signature & membership tag
                    // TODO #106: Support external senders
                    if plaintext.is_proposal()
                        && plaintext.sender.is_member()
                        && self.group.verify_membership_tag(&plaintext).is_err()
                    {
                        // If there is a callback for that event we should call it
                        self.invalid_message_event(InvalidMessageError::MembershipTagMismatch);
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
                MLSPlaintextContentType::Proposal(_) => {
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
                        self.invalid_message_event(
                            InvalidMessageError::CommitWithInvalidProposals("".into()),
                        );
                    }
                }
                MLSPlaintextContentType::Commit(ref commit) => {
                    // Validate inline proposals
                    if !self.validate_inline_proposals(
                        &commit.proposals,
                        &plaintext.sender.sender,
                        &indexed_members,
                    ) {
                        // If not all of them are valid, call error function callback
                        self.invalid_message_event(
                            InvalidMessageError::CommitWithInvalidProposals(
                                "Not all of them are valid".into(),
                            ),
                        );
                        // And move on to the next message
                        continue;
                    }
                    // If all proposals were valid, we continue with applying the Commit
                    // message
                    let proposals = &self
                        .pending_proposals
                        .iter()
                        .collect::<Vec<&MLSPlaintext>>();
                    match self
                        .group
                        .apply_commit(&plaintext, proposals, &self.own_kpbs)
                    {
                        Ok(()) => {
                            // Since the Commit was applied without errors, we can call all
                            // corresponding callback functions for the whole proposal list
                            self.send_events(
                                self.ciphersuite(),
                                &commit.proposals,
                                plaintext.sender.sender,
                                &indexed_members,
                            );
                            // We don't need the pending proposals and key package bundles any
                            // longer
                            self.pending_proposals.clear();
                            self.own_kpbs.clear();
                        }
                        Err(apply_commit_error) => match apply_commit_error {
                            GroupError::ApplyCommitError(ApplyCommitError::SelfRemoved) => {
                                // Send out events
                                self.send_events(
                                    self.ciphersuite(),
                                    &commit.proposals,
                                    plaintext.sender.sender,
                                    &indexed_members,
                                );
                                // The group is no longer active
                                self.active = false;
                            }
                            GroupError::ApplyCommitError(e) => {
                                self.invalid_message_event(InvalidMessageError::CommitError(e));
                            }
                            _ => {
                                panic!("apply_commit_error did not return an ApplyCommitError.");
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

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(())
    }

    // === Application messages ===

    /// Creates an application message.
    /// Returns `ManagedGroupError::UseAfterEviction(UseAfterEviction::Error)`
    /// if the member is no longer part of the group.
    /// Returns `ManagedGroupError::PendingProposalsExist` if pending proposals
    /// exist. In that case `.process_pending_proposals()` must be called first
    /// and incoming messages from the DS must be processed afterwards.
    pub fn create_message(&mut self, message: &[u8]) -> Result<MLSMessage, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        if !self.pending_proposals.is_empty() {
            return Err(ManagedGroupError::PendingProposalsExist(
                PendingProposalsError::Exists,
            ));
        }

        let credential_bundle = &self.credential_bundle()?;

        let ciphertext = self.group.create_application_message(
            &self.aad,
            message,
            credential_bundle.credential_bundle(),
            self.configuration().padding_size(),
        )?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(MLSMessage::Ciphertext(ciphertext))
    }

    /// Process pending proposals
    pub fn process_pending_proposals(
        &mut self,
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        // Include pending proposals into Commit
        let messages_to_commit: Vec<&MLSPlaintext> = self.pending_proposals.iter().collect();

        let credential_bundle = &self.credential_bundle()?;

        // Create Commit over all pending proposals
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            credential_bundle.credential_bundle(),
            &messages_to_commit,
            &[],
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
        key_length: usize,
    ) -> Result<Vec<u8>, ManagedGroupError> {
        if self.active {
            Ok(self.group.export_secret(label, key_length)?)
        } else {
            Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error))
        }
    }

    /// Returns the authentication secret
    pub fn authentication_secret(&self) -> Vec<u8> {
        self.group.authentication_secret().to_vec()
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
    /// `UseAfterEviction` error.
    pub fn credential(&self) -> Result<Credential, ManagedGroupError> {
        if !self.is_active() {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        let tree = self.group.tree();
        Ok(tree.own_key_package().credential().clone())
    }

    /// Tries to obtain the credential bundle corresponding to the group's
    /// credential from the key store. Throws an error if the key store doesn't
    /// contain the `CredentialBundle` corresponding to the `Credential` in our
    /// leaf.
    pub fn credential_bundle(
        &self,
    ) -> Result<Ref<'_, RefCell<CredentialBundle>>, ManagedGroupError> {
        Ok(self
            .key_store
            .get_credential_bundle(self.credential()?.signature_key())
            .ok_or(KeyStoreError::NoMatchingCredentialBundle)?)
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
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<(Vec<MLSMessage>, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential_bundle = &self.credential_bundle()?;

        // If a KeyPackageBundle was provided, create an UpdateProposal
        let mut plaintext_messages = if let Some(key_package_bundle) = key_package_bundle_option {
            let update_proposal = self.group.create_update_proposal(
                &self.aad,
                credential_bundle.credential_bundle(),
                key_package_bundle.key_package().clone(),
            )?;
            self.own_kpbs.push(key_package_bundle);
            vec![update_proposal]
        } else {
            vec![]
        };

        // Include pending proposals into Commit
        let messages_to_commit: Vec<&MLSPlaintext> = self
            .pending_proposals
            .iter()
            .chain(plaintext_messages.iter())
            .collect();

        // Create Commit over all proposals
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            credential_bundle.credential_bundle(),
            &messages_to_commit,
            &[],
            true, /* force_self_update */
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

        // Convert MLSPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_messages(plaintext_messages)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_messages, welcome_option))
    }

    /// Creates a proposal to update the own leaf node
    pub fn propose_self_update(
        &mut self,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        let tree = self.group.tree();
        let existing_key_package = tree.own_key_package();
        let cb = &self.credential_bundle()?;
        let key_package_bundle = match key_package_bundle_option {
            Some(kpb) => kpb,
            None => {
                let mut key_package_bundle =
                    KeyPackageBundle::from_rekeyed_key_package(existing_key_package);
                key_package_bundle.sign(cb.credential_bundle());
                key_package_bundle
            }
        };

        let plaintext_messages = vec![self.group.create_update_proposal(
            &self.aad,
            cb.credential_bundle(),
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
    pub fn pending_proposals(&self) -> &[MLSPlaintext] {
        &self.pending_proposals
    }

    // === Load & save ===

    /// Loads the state from persisted state
    pub fn load<R: Read>(
        reader: R,
        key_store: &'a KeyStore,
        callbacks: &ManagedGroupCallbacks,
    ) -> Result<ManagedGroup<'a>, Error> {
        let serialized_managed_group: SerializedManagedGroup = serde_json::from_reader(reader)?;
        Ok(serialized_managed_group.into_managed_group(key_store, callbacks))
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
        mut plaintext_messages: Vec<MLSPlaintext>,
    ) -> Result<Vec<MLSMessage>, ManagedGroupError> {
        let mut out = Vec::with_capacity(plaintext_messages.len());
        for plaintext in plaintext_messages.drain(..) {
            let msg = match self.configuration().handshake_message_format {
                HandshakeMessageFormat::Plaintext => MLSMessage::Plaintext(plaintext),
                HandshakeMessageFormat::Ciphertext => {
                    let ciphertext = self
                        .group
                        .encrypt(plaintext, self.configuration().padding_size())?;
                    MLSMessage::Ciphertext(ciphertext)
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

    /// Send out the corresponding events for the proposals covered by the
    /// Commit
    fn send_events(
        &self,
        ciphersuite: &Ciphersuite,
        proposals: &[ProposalOrRef],
        sender: LeafIndex,
        indexed_members: &HashMap<LeafIndex, Credential>,
    ) {
        // We want to send the events in the order specified by the committer.
        // We convert the pending proposals to a list of references
        let pending_proposals_list = self
            .pending_proposals
            .iter()
            .collect::<Vec<&MLSPlaintext>>();
        // Build a proposal queue for easier searching
        let pending_proposals_queue =
            ProposalQueue::from_proposals_by_reference(ciphersuite, &pending_proposals_list);
        for proposal_or_ref in proposals {
            match proposal_or_ref {
                ProposalOrRef::Proposal(proposal) => {
                    self.send_proposal_event(proposal, sender, indexed_members);
                }
                ProposalOrRef::Reference(proposal_reference) => {
                    if let Some(queued_proposal) = pending_proposals_queue.get(proposal_reference) {
                        self.send_proposal_event(
                            queued_proposal.proposal(),
                            queued_proposal.sender().to_leaf_index(),
                            indexed_members,
                        );
                    }
                }
            }
        }
    }

    /// Send out the corresponding events for the pending proposal list.
    fn send_proposal_event(
        &self,
        proposal: &Proposal,
        sender: LeafIndex,
        indexed_members: &HashMap<LeafIndex, Credential>,
    ) {
        let sender_credential = &indexed_members[&sender];
        match proposal {
            // Add proposals
            Proposal::Add(add_proposal) => {
                if let Some(member_added) = self.managed_group_config.callbacks.member_added {
                    member_added(
                        &self,
                        &self.aad,
                        sender_credential,
                        add_proposal.key_package.credential(),
                    )
                }
            }
            // Update proposals
            Proposal::Update(update_proposal) => {
                if let Some(member_updated) = self.managed_group_config.callbacks.member_updated {
                    member_updated(&self, &self.aad, update_proposal.key_package.credential())
                }
            }
            // Remove proposals
            Proposal::Remove(remove_proposal) => {
                let removal = Removal::new(
                    &indexed_members[&self.group.tree().own_node_index()],
                    sender_credential,
                    &indexed_members[&LeafIndex::from(remove_proposal.removed)],
                );

                if let Some(member_removed) = self.managed_group_config.callbacks.member_removed {
                    member_removed(&self, &self.aad, &removal)
                }
            }
            // PSK proposals
            Proposal::PreSharedKey(psk_proposal) => {
                let psk_id = &psk_proposal.psk;

                if let Some(psk_received) = self.managed_group_config.callbacks.psk_received {
                    psk_received(&self, &self.aad, psk_id)
                }
            }
            // ReInit proposals
            Proposal::ReInit(reinit_proposal) => {
                if let Some(reinit_received) = self.managed_group_config.callbacks.reinit_received {
                    reinit_received(&self, &self.aad, &reinit_proposal)
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
pub enum MLSMessage {
    /// An OpenMLS `MLSPlaintext`.
    Plaintext(MLSPlaintext),

    /// An OpenMLS `MLSCiphertext`.
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

impl MLSMessage {
    /// Get the group ID as plain byte vector.
    pub fn group_id(&self) -> Vec<u8> {
        match self {
            MLSMessage::Ciphertext(m) => m.group_id.as_slice(),
            MLSMessage::Plaintext(m) => m.group_id().as_slice(),
        }
    }

    /// Get the epoch as plain u64.
    pub fn epoch(&self) -> u64 {
        match self {
            MLSMessage::Ciphertext(m) => m.epoch.0,
            MLSMessage::Plaintext(m) => m.epoch().0,
        }
    }

    /// Returns `true` if this is a handshake message and `false` otherwise.
    pub fn is_handshake_message(&self) -> bool {
        match self {
            MLSMessage::Ciphertext(m) => m.is_handshake_message(),
            MLSMessage::Plaintext(m) => m.is_handshake_message(),
        }
    }
}
