use crate::creds::*;
use crate::group::*;

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
    pub(crate) validate_add: Option<ValidateAdd>,
    pub(crate) validate_remove: Option<ValidateRemove>,
    // Event listeners
    pub(crate) member_added: Option<MemberAdded>,
    pub(crate) member_removed: Option<MemberRemoved>,
    pub(crate) member_updated: Option<MemberUpdated>,
    pub(crate) app_message_received: Option<AppMessageReceived>,
    pub(crate) invalid_message_received: Option<InvalidMessageReceived>,
    pub(crate) error_occured: Option<ErrorOccured>,
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

/// This enum lists the 4 different variants of a removal, depending on who the
/// remover and who the leaver is.
pub enum Removal<'a> {
    WeLeft,
    TheyLeft(&'a Credential),
    WeWereRemovedBy(&'a Credential),
    TheyWereRemovedBy(&'a Credential, &'a Credential),
}

impl<'a> Removal<'a> {
    pub fn new(
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

/// Validator function for AddProposals
/// `(managed_group: &ManagedGroup, sender: &Credential, added_member:
/// &Credential) -> bool`
pub type ValidateAdd = fn(&ManagedGroup, &Credential, &Credential) -> bool;
/// Validator function for RemoveProposals
/// `(managed_group: &ManagedGroup, sender: &Credential,
/// removed_member: &Credential) -> bool`
pub type ValidateRemove = fn(&ManagedGroup, &Credential, &Credential) -> bool;
/// Event listener function for AddProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential,
/// added_member: &Credential)`
pub type MemberAdded = fn(&ManagedGroup, &[u8], &Credential, &Credential);
/// Event listener function for RemoveProposals when a member was removed
/// `(managed_group: &ManagedGroup, aad: &[u8], sender:
/// &Credential, removal: &Removal)`
pub type MemberRemoved = fn(&ManagedGroup, &[u8], &Removal);
/// Event listener function for UpdateProposals
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential)`
pub type MemberUpdated = fn(&ManagedGroup, &[u8], &Credential);
/// Event listener function for application messages
/// `(managed_group: &ManagedGroup, aad: &[u8], sender: &Credential, message:
/// &[u8])`
pub type AppMessageReceived = fn(&ManagedGroup, &[u8], &Credential, &[u8]);
/// Event listener function for invalid messages
/// `(managed_group: &ManagedGroup, error: InvalidMessageError)`
pub type InvalidMessageReceived = fn(&ManagedGroup, InvalidMessageError);
/// Event listener function for errors that occur
/// `(managed_group: &ManagedGroup, error: ManagedGroupError)`
pub type ErrorOccured = fn(&ManagedGroup, ManagedGroupError);
