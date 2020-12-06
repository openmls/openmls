use crate::creds::*;
use crate::group::*;

/// Collection of callback functions that are passed to a `ManagedGroup` as part
/// of the configurations. All callback functions are optional.
///
/// ## Validators
///
/// Validator callback functions are called when Proposals are processed through
/// [process_messages()](`ManagedGroup::process_messages()`). If no
/// validator function is specified for a certain proposal type, any
/// semantically valid proposal will be accepted. Validator functions must
/// return a `bool`, that indicates whether the proposal is accepted by the
/// application policy.
///  - `true` means the proposal should be accepted
///  - `false` means the proposal should be rejected
///
/// The validator functions are:
/// ```
/// # use openmls::prelude::{ManagedGroup, Credential};
/// pub type ValidateAdd =
///     fn(managed_group: &ManagedGroup, sender: &Credential, added_member: &Credential) -> bool;
/// pub type ValidateRemove =
///     fn(managed_group: &ManagedGroup, sender: &Credential, removed_member: &Credential) -> bool;
/// ```
///
/// ## Auto-save
///
/// The auto-save callback is called whenever the group state was modified and
/// needs to be persisted. The callback function should then call
/// [managed_group.save()](`ManagedGroup::save()`) to persist the group state.
///
/// ```
/// # use openmls::prelude::{ManagedGroup, Credential};
/// pub type AutoSave = fn(managed_group: &ManagedGroup);
/// ```
///
/// ## Event listeners
///
/// Event listeners get called when certain messages are parsed, or other events
/// occur. The event listeners are:
/// ```
/// # use openmls::prelude::{ManagedGroup, Credential, Removal, ManagedGroupError, InvalidMessageError};
/// pub type MemberAdded = fn(
///     managed_group: &ManagedGroup,
///     aad: &[u8],
///     sender: &Credential,
///     added_member: &Credential,
/// );
/// pub type MemberRemoved = fn(managed_group: &ManagedGroup, aad: &[u8], removal: &Removal);
/// pub type MemberUpdated =
///     fn(managed_group: &ManagedGroup, aad: &[u8], updated_member: &Credential);
/// pub type AppMessageReceived =
///     fn(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential, message: &[u8]);
/// pub type InvalidMessageReceived = fn(managed_group: &ManagedGroup, error: InvalidMessageError);
/// pub type ErrorOccured = fn(managed_group: &ManagedGroup, error: ManagedGroupError);
/// ```
#[derive(Default, Clone)]
pub struct ManagedGroupCallbacks {
    // Validator functions
    pub(crate) validate_add: Option<ValidateAdd>,
    pub(crate) validate_remove: Option<ValidateRemove>,
    // Auto-save
    pub(crate) auto_save: Option<AutoSave>,
    // Event listeners
    pub(crate) member_added: Option<MemberAdded>,
    pub(crate) member_removed: Option<MemberRemoved>,
    pub(crate) member_updated: Option<MemberUpdated>,
    pub(crate) app_message_received: Option<AppMessageReceived>,
    pub(crate) invalid_message_received: Option<InvalidMessageReceived>,
    pub(crate) error_occured: Option<ErrorOccured>,
}

impl<'a> ManagedGroupCallbacks {
    pub fn new() -> Self {
        Self {
            validate_add: None,
            validate_remove: None,
            auto_save: None,
            member_added: None,
            member_removed: None,
            member_updated: None,
            app_message_received: None,
            invalid_message_received: None,
            error_occured: None,
        }
    }
    /// Validator function for AddProposals
    pub fn with_validate_add(mut self, validate_add: ValidateAdd) -> Self {
        self.validate_add = Some(validate_add);
        self
    }
    /// Validator function for RemoveProposals
    pub fn with_validate_remove(mut self, validate_remove: ValidateRemove) -> Self {
        self.validate_remove = Some(validate_remove);
        self
    }
    /// Auto-save callback
    pub fn with_auto_save(mut self, auto_save: AutoSave) -> Self {
        self.auto_save = Some(auto_save);
        self
    }
    /// Event listener function for AddProposals
    pub fn with_member_added(mut self, member_added: MemberAdded) -> Self {
        self.member_added = Some(member_added);
        self
    }
    /// Event listener function for RemoveProposals when a member was removed
    pub fn with_member_removed(mut self, member_removed: MemberRemoved) -> Self {
        self.member_removed = Some(member_removed);
        self
    }
    /// Event listener function for UpdateProposals
    pub fn with_member_updated(mut self, member_updated: MemberUpdated) -> Self {
        self.member_updated = Some(member_updated);
        self
    }
    /// Event listener function for application messages
    pub fn with_app_message_received(mut self, app_message_received: AppMessageReceived) -> Self {
        self.app_message_received = Some(app_message_received);
        self
    }
    /// Event listener function for invalid messages
    pub fn with_invalid_message_received(
        mut self,
        invalid_message_received: InvalidMessageReceived,
    ) -> Self {
        self.invalid_message_received = Some(invalid_message_received);
        self
    }
    /// Event listener function for errors that occur
    pub fn with_error_occured(mut self, error_occured: ErrorOccured) -> Self {
        self.error_occured = Some(error_occured);
        self
    }
}

impl std::fmt::Debug for ManagedGroupCallbacks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ManagedGroupCallbacks")
    }
}

impl PartialEq for ManagedGroupCallbacks {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

/// This enum lists the 4 different variants of a removal, depending on who the
/// remover and who the leaver is.
pub enum Removal<'a> {
    ///  We previously issued a RemoveProposal for ourselves and this was now
    /// commited by someone else
    WeLeft,
    /// Another member issued a RemoveProposal for itself that was now committed
    TheyLeft(&'a Credential),
    /// Another member issued a RemoveProposal for ourselves that was now
    /// committed
    WeWereRemovedBy(&'a Credential),
    /// Member A issued a RemoveProposal for member B that was now commited
    TheyWereRemovedBy(&'a Credential, &'a Credential),
}

impl<'a> Removal<'a> {
    pub(crate) fn new(
        own_credential: &'a Credential,
        remover_credential: &'a Credential,
        leaver_credential: &'a Credential,
    ) -> Self {
        if leaver_credential == own_credential {
            if remover_credential == own_credential {
                Self::WeLeft
            } else {
                Self::WeWereRemovedBy(remover_credential)
            }
        } else if leaver_credential == remover_credential {
            Self::TheyLeft(leaver_credential)
        } else {
            Self::TheyWereRemovedBy(remover_credential, leaver_credential)
        }
    }
}

// Validators
pub type ValidateAdd =
    fn(managed_group: &ManagedGroup, sender: &Credential, added_member: &Credential) -> bool;
pub type ValidateRemove =
    fn(managed_group: &ManagedGroup, sender: &Credential, removed_member: &Credential) -> bool;

// Auto-save
pub type AutoSave = fn(managed_group: &ManagedGroup);

// Event listeners
pub type MemberAdded =
    fn(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential, added_member: &Credential);
pub type MemberRemoved = fn(managed_group: &ManagedGroup, aad: &[u8], removal: &Removal);
pub type MemberUpdated = fn(managed_group: &ManagedGroup, aad: &[u8], updated_member: &Credential);
pub type AppMessageReceived =
    fn(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential, message: &[u8]);
pub type InvalidMessageReceived = fn(managed_group: &ManagedGroup, error: InvalidMessageError);
pub type ErrorOccured = fn(managed_group: &ManagedGroup, error: ManagedGroupError);
