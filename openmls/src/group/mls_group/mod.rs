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
mod test_mls_group;
mod updates;

use crate::credentials::CredentialBundle;
use crate::{treesync::node::Node, treesync::LeafIndex};

use openmls_traits::{key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};

use crate::{
    ciphersuite::signable::Signable,
    credentials::Credential,
    framing::*,
    group::*,
    key_packages::KeyPackageBundlePayload,
    key_packages::{KeyPackage, KeyPackageBundle},
    messages::{proposals::*, Welcome},
    schedule::ResumptionSecret,
};

use std::io::{Error, Read, Write};

pub use config::*;
pub use errors::{
    EmptyInputError, InvalidMessageError, MlsGroupError, PendingProposalsError, UseAfterEviction,
};
pub(crate) use resumption::ResumptionSecretStore;
use ser::*;

use super::past_secrets::MessageSecretsStore;
use super::proposals::{ProposalStore, StagedProposal};

/// A `MlsGroup` represents an [CoreGroup] with
/// an easier, high-level API designed to be used in production. The API exposes
/// high level functions to manage a group by adding/removing members, get the
/// current member list, etc.
///
/// The API is modeled such that it can serve as a direct interface to the
/// Delivery Service. Functions that modify the public state of the group will
/// return a `Vec<MLSMessage>` that can be sent to the Delivery
/// Service directly. Conversely, incoming messages from the Delivery Service
/// can be fed into [process_message()](`MlsGroup::process_message()`).
///
/// A `MlsGroup` has an internal queue of pending proposals that builds up
/// as new messages are processed. When creating proposals, those messages are
/// not automatically appended to this queue, instead they have to be processed
/// again through [process_message()](`MlsGroup::process_message()`). This
/// allows the Delivery Service to reject them (e.g. if they reference the wrong
/// epoch).
///
/// If incoming messages or applied operations are semantically or syntactically
/// incorrect, an error event will be returned with a corresponding error
/// message and the state of the group will remain unchanged.
///
/// The application policy for the group can be enforced by implementing the
/// validator callback functions and selectively allowing/ disallowing each
/// operation (see [`MlsGroupCallbacks`])
///
/// Changes to the group state are dispatched as events through callback
/// functions (see [`MlsGroupCallbacks`]).
#[derive(Debug)]
pub struct MlsGroup {
    // The group configuration. See `MlsGroupCongig` for more information.
    mls_group_config: MlsGroupConfig,
    // the internal `CoreGroup` used for lower level operations. See `CoreGroup` for more
    // information.
    group: CoreGroup,
    // A [ProposalStore] that stores incoming proposals from the DS within one epoch.
    // The store is emptied after every epoch change.
    proposal_store: ProposalStore,
    // A [MessageSecretsStore] that stores message secrets from past epochs in order to be able to decrypt
    // application messages from previous epochs.
    message_secrets_store: MessageSecretsStore,
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

impl MlsGroup {
    // === Configuration ===

    /// Gets the configuration
    pub fn configuration(&self) -> &MlsGroupConfig {
        &self.mls_group_config
    }

    /// Sets the configuration
    pub fn set_configuration(&mut self, mls_group_config: &MlsGroupConfig) {
        self.mls_group_config = mls_group_config.clone();

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
    pub fn credential(&self) -> Result<Credential, MlsGroupError> {
        if !self.is_active() {
            return Err(MlsGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        let tree = self.group.treesync();
        Ok(tree.own_leaf_node()?.key_package().credential().clone())
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
    pub fn load<R: Read>(reader: R) -> Result<MlsGroup, Error> {
        let serialized_mls_group: SerializedMlsGroup = serde_json::from_reader(reader)?;
        Ok(serialized_mls_group.into_mls_group())
    }

    /// Persists the state
    pub fn save<W: Write>(&mut self, writer: &mut W) -> Result<(), Error> {
        let serialized_mls_group = serde_json::to_string_pretty(self)?;
        writer.write_all(&serialized_mls_group.into_bytes())?;
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
        self.group.treesync().export_nodes()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn export_group_context(&self) -> &GroupContext {
        self.group.context()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn tree_hash(&self) -> &[u8] {
        self.group.treesync().tree_hash()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn print_tree(&self, message: &str) {
        print_tree(self.group.treesync(), message)
    }

    /// Get the underlying [CoreGroup].
    #[cfg(any(feature = "test-utils", test))]
    pub fn group(&self) -> &CoreGroup {
        &self.group
    }
}

// Private methods of MlsGroup
impl MlsGroup {
    /// Converts MlsPlaintext to MLSMessage. Depending on whether handshake
    /// message should be encrypted, MlsPlaintext messages are encrypted to
    /// MlsCiphertext first.
    fn plaintext_to_mls_message(
        &mut self,
        plaintext: MlsPlaintext,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsMessageOut, MlsGroupError> {
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
        FramingParameters::new(&self.aad, self.mls_group_config.wire_format)
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
