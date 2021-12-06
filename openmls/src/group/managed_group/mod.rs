mod application;
pub mod config;
mod creation;
pub mod errors;
mod exporting;
mod membership;
pub mod processing;
mod resumption;
mod ser;
#[cfg(test)]
mod test_managed_group;
mod updates;

use crate::credentials::CredentialBundle;
use crate::{binary_tree::LeafIndex, treesync::node::Node};

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
};

use std::io::{Error, Read, Write};

pub use config::*;
pub use errors::{
    EmptyInputError, InvalidMessageError, ManagedGroupError, PendingProposalsError,
    UseAfterEviction,
};
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
    // A flag that indicates if the group state has changed and needs to be persisted again. The value
    // is set to `InnerState::Changed` whenever an the internal group state is change and is set to
    // `InnerState::Persisted` once the state has been persisted.
    state_changed: InnerState,
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

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();
    }

    /// Gets the AAD used in the framing
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Sets the AAD used in the framing
    pub fn set_aad(&mut self, aad: &[u8]) {
        self.aad = aad.to_vec();

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();
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
        Ok(tree.own_leaf_node()?.credential().clone())
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
    pub fn load<R: Read>(reader: R) -> Result<ManagedGroup, Error> {
        let serialized_managed_group: SerializedManagedGroup = serde_json::from_reader(reader)?;
        Ok(serialized_managed_group.into_managed_group())
    }

    /// Persists the state
    pub fn save<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        let serialized_managed_group = serde_json::to_string_pretty(self)?;
        writer.write_all(&serialized_managed_group.into_bytes())?;
        self.state_changed = InnerState::Persisted;
        Ok(())
    }

    /// Returns `true` if the internal state has changed and needs to be persisted and
    /// `false` otherwise. Calling [save()] resets the value to `false`.
    pub fn state_changed(&self) -> InnerState {
        self.state_changed
    }

    // === Extensions ===

    /// Export the Ratchet Tree
    pub fn export_ratchet_tree(&self) -> Vec<Option<Node>> {
        self.group.tree().export_nodes()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn export_group_context(&self) -> &GroupContext {
        self.group.context()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn tree_hash(&self, backend: &impl OpenMlsCryptoProvider) -> &[u8] {
        self.group.tree().tree_hash()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn print_tree(&self, message: &str) {
        _print_tree(&self.group.tree(), message)
    }

    /// Get the underlying [MlsGroup].
    #[cfg(any(feature = "test-utils", test))]
    pub fn group(&self) -> &MlsGroup {
        &self.group
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
            WireFormat::MlsPlaintext => MlsMessageOut::Plaintext(Box::new(plaintext)),
            WireFormat::MlsCiphertext => {
                let ciphertext =
                    self.group
                        .encrypt(plaintext, self.configuration().padding_size(), backend)?;
                MlsMessageOut::Ciphertext(Box::new(ciphertext))
            }
        };
        Ok(msg)
    }

    /// Arm the state changed flag function
    fn flag_state_change(&mut self) {
        self.state_changed = InnerState::Changed;
    }

    /// Group framing parameters
    fn framing_parameters(&self) -> FramingParameters {
        FramingParameters::new(&self.aad, self.managed_group_config.wire_format)
    }
}

/// `Enum` that indicates whether the inner group state has been modified since the last time it was persisted.
/// `InnerState::Changed` indicates that the state has changed and that [`.save()`] should be called.
/// `InnerState::Persisted` indicates that the state has not been modified and therefore doesn't need to be persisted.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum InnerState {
    Changed,
    Persisted,
}
