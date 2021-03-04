use crate::credentials::*;
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

#[derive(Default, Copy, Clone)]
pub struct ManagedGroupCallbacks {
    // Validator functions
    pub(crate) validate_add: Option<ValidateAdd>,
    pub(crate) validate_remove: Option<ValidateRemove>,
    // Auto-save
    pub(crate) auto_save: Option<AutoSave>,
}

impl<'a> ManagedGroupCallbacks {
    pub fn new() -> Self {
        Self {
            validate_add: None,
            validate_remove: None,
            auto_save: None,
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

// Validators
pub type ValidateAdd =
    fn(managed_group: &ManagedGroup, sender: &Credential, added_member: &Credential) -> bool;
pub type ValidateRemove =
    fn(managed_group: &ManagedGroup, sender: &Credential, removed_member: &Credential) -> bool;

// Auto-save
pub type AutoSave = fn(managed_group: &ManagedGroup);
