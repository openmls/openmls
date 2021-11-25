mod application;
pub mod callbacks;
pub mod config;
mod creation;
pub mod errors;
pub mod events;
mod exporting;
mod membership;
mod processing;
mod resumption;
mod ser;
#[cfg(test)]
mod test_managed_group;
mod updates;
pub mod validation;

use crate::credentials::CredentialBundle;
use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

use crate::{
    ciphersuite::signable::Signable,
    credentials::Credential,
    framing::*,
    group::*,
    key_packages::{KeyPackage, KeyPackageBundle},
    messages::{proposals::*, Welcome},
    prelude::KeyPackageBundlePayload,
    schedule::ResumptionSecret,
    tree::{index::LeafIndex, node::Node},
};

use std::collections::HashMap;
use std::io::{Error, Read, Write};

#[cfg(any(feature = "test-utils", test))]
use std::cell::Ref;

pub use callbacks::*;
pub use config::*;
pub use errors::{
    EmptyInputError, InvalidMessageError, ManagedGroupError, PendingProposalsError,
    UseAfterEviction,
};
pub use events::*;
pub(crate) use resumption::ResumptionSecretStore;
use ser::*;

use super::proposals::{ProposalStore, StagedProposal};

/// A `ManagedGroup` represents an [MlsGroup] with
/// an easier, high-level API designed to be used in production. The API exposes
/// high level functions to manage a group by adding/removing members, get the
/// current member list, etc.
///
/// The API is modeled such that it can serve as a direct interface to the
/// Delivery Service. Functions that modify the public state of the group will
/// return a `Vec<MLSMessage>` that can be sent to the Delivery
/// Service directly. Conversely, incoming messages from the Delivery Service
/// can be fed into [process_message()](`ManagedGroup::process_message()`).
///
/// A `ManagedGroup` has an internal queue of pending proposals that builds up
/// as new messages are processed. When creating proposals, those messages are
/// not automatically appended to this queue, instead they have to be processed
/// again through [process_message()](`ManagedGroup::process_message()`). This
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
    // A [ProposalStore] that stores incoming proposals from the DS within one epoch.
    // The store is emptied after every epoch change.
    proposal_store: ProposalStore,
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

    /// Returns an `Iterator` over staged proposals.
    pub fn pending_proposals(&self) -> impl Iterator<Item = &StagedProposal> {
        self.proposal_store.proposals()
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

    #[cfg(any(feature = "test-utils", test))]
    pub fn export_path_secrets(&self) -> Ref<[crate::messages::PathSecret]> {
        Ref::map(self.group.tree(), |tree| tree.private_tree().path_secrets())
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn export_group_context(&self) -> &GroupContext {
        self.group.context()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn tree_hash(&self, backend: &impl OpenMlsCryptoProvider) -> Vec<u8> {
        self.group.tree().tree_hash(backend)
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn print_tree(&self, message: &str) {
        _print_tree(&self.group.tree(), message)
    }
}

// Private methods of ManagedGroup
impl ManagedGroup {
    /// Converts MlsPlaintext to MLSMessage. Depending on whether handshake
    /// message should be encrypted, MlsPlaintext messages are encrypted to
    /// MlsCiphertext first.
    fn plaintext_to_mls_message(
        &mut self,
        plaintext: MlsPlaintext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        let msg = match self.configuration().wire_format() {
            WireFormat::MlsPlaintext => MlsMessageOut::Plaintext(plaintext),
            WireFormat::MlsCiphertext => {
                let ciphertext =
                    self.group
                        .encrypt(plaintext, self.configuration().padding_size(), backend)?;
                MlsMessageOut::Ciphertext(ciphertext)
            }
        };
        Ok(msg)
    }

    /// Validate all pending proposals. The function returns `true` only if all
    /// proposals are valid.
    fn validate_proposal(
        &self,
        proposal: &Proposal,
        sender: LeafIndex,
        indexed_members: &HashMap<LeafIndex, Credential>,
    ) -> bool {
        let sender = &indexed_members[&sender];
        match proposal {
            // Validate add proposals
            Proposal::Add(add_proposal) => {
                if let Some(validate_add) = self.managed_group_config.callbacks.validate_add {
                    if !validate_add(self, sender, add_proposal.key_package.credential()) {
                        return false;
                    }
                }
            }
            // Validate remove proposals
            Proposal::Remove(remove_proposal) => {
                if let Some(validate_remove) = self.managed_group_config.callbacks.validate_remove {
                    if !validate_remove(
                        self,
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
            Proposal::ExternalInit(_) => unimplemented!("See #556"),
            Proposal::AppAck(_) => unimplemented!("See #291"),
            Proposal::GroupContextExtensions(_) => {}
        }
        true
    }

    /// Validates the inline proposals from a Commit message
    fn validate_inline_proposals(
        &self,
        proposals: &[ProposalOrRef],
        sender: LeafIndex,
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

    /// Auto-save function
    fn auto_save(&self) {
        if let Some(auto_save) = self.managed_group_config.callbacks.auto_save {
            auto_save(self);
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

    /// Group framing parameters
    fn framing_parameters(&self) -> FramingParameters {
        FramingParameters::new(&self.aad, self.managed_group_config.wire_format)
    }
}
