use crate::credentials::*;
use crate::group::*;
use crate::messages::proposals::*;
use crate::schedule::psk::*;

/// Group event that occured while processing messages in `ManagedGroup`.
#[derive(Debug, PartialEq, Clone)]
pub enum GroupEvent {
    MemberAdded(MemberAddedEvent),
    MemberRemoved(MemberRemovedEvent),
    MemberUpdated(MemberUpdatedEvent),
    PskReceived(PskReceivedEvent),
    ReInit(ReInitEvent),
    ApplicationMessage(ApplicationMessageEvent),
    Error(ErrorEvent),
}

// Member events

/// Event that occurs when member `sender` adds member `added_member`.
#[derive(Debug, PartialEq, Clone)]
pub struct MemberAddedEvent {
    aad: Vec<u8>,
    sender: Credential,
    added_member: Credential,
}

impl MemberAddedEvent {
    pub(crate) fn new(aad: Vec<u8>, sender: Credential, added_member: Credential) -> Self {
        Self {
            aad,
            sender,
            added_member,
        }
    }

    /// Get a reference to the event's aad.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Get a reference to the event's sender.
    pub fn sender(&self) -> &Credential {
        &self.sender
    }

    /// Get a reference to the event's added member credential.
    pub fn added_member(&self) -> &Credential {
        &self.added_member
    }
}

/// Event that occurs when a member leaves/is removed from the group.
/// The exact context of the removal is explained in the `Removal` enum.
#[derive(Debug, PartialEq, Clone)]
pub struct MemberRemovedEvent {
    aad: Vec<u8>,
    removal: Removal,
}

impl MemberRemovedEvent {
    pub(crate) fn new(aad: Vec<u8>, removal: Removal) -> Self {
        Self { aad, removal }
    }

    /// Get a reference to the event's aad.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Get a reference to the event's removal.
    pub fn removal(&self) -> &Removal {
        &self.removal
    }
}

/// Event that occurs when a member updates its leaf.
/// `updated_member` contains the new credential.
#[derive(Debug, PartialEq, Clone)]
pub struct MemberUpdatedEvent {
    aad: Vec<u8>,
    updated_member: Credential,
}

impl MemberUpdatedEvent {
    pub(crate) fn new(aad: Vec<u8>, updated_member: Credential) -> Self {
        Self {
            aad,
            updated_member,
        }
    }

    /// Get a reference to the event's aad.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Get a reference to the event's updated member.
    pub fn updated_member(&self) -> &Credential {
        &self.updated_member
    }
}

// PSK events

/// Event that occurs when  a PSK is received. `psk_id` contains the PSK ID.
#[derive(Debug, PartialEq, Clone)]
pub struct PskReceivedEvent {
    aad: Vec<u8>,
    psk_id: PreSharedKeyId,
}

impl PskReceivedEvent {
    pub(crate) fn new(aad: Vec<u8>, psk_id: PreSharedKeyId) -> Self {
        Self { aad, psk_id }
    }

    /// Get a reference to the event's aad.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Get a reference to the event's psk id.
    pub fn psk_id(&self) -> &PreSharedKeyId {
        &self.psk_id
    }
}

/// Event that occurs when a `ReInitProposal` is received.
/// `re_init_proposal` contains the `ReInitProposal`.
#[derive(Debug, PartialEq, Clone)]
pub struct ReInitEvent {
    aad: Vec<u8>,
    re_init_proposal: ReInitProposal,
}

impl ReInitEvent {
    pub(crate) fn new(aad: Vec<u8>, re_init_proposal: ReInitProposal) -> Self {
        Self {
            aad,
            re_init_proposal,
        }
    }

    /// Get a reference to the event's aad.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Get a reference to the event's psk id.
    pub fn psk_id(&self) -> &ReInitProposal {
        &self.re_init_proposal
    }
}

// Application messages

/// Event that occurs when an application message is received.
/// `sender` contains the message's sender and `message` contains
/// the application message.
#[derive(Debug, PartialEq, Clone)]
pub struct ApplicationMessageEvent {
    aad: Vec<u8>,
    sender: Credential,
    message: Vec<u8>,
}

impl ApplicationMessageEvent {
    pub(crate) fn new(aad: Vec<u8>, sender: Credential, message: Vec<u8>) -> Self {
        Self {
            aad,
            sender,
            message,
        }
    }

    /// Get a reference to the event's aad.
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Get a reference to the event's sender.
    pub fn sender(&self) -> &Credential {
        &self.sender
    }

    /// Get a reference to the event's message.
    pub fn message(&self) -> &[u8] {
        &self.message
    }
}

/// Event that occurs when an error occurred while processing messages in a group.
/// `error` contains the specific error that occurred.
#[derive(Debug, PartialEq, Clone)]
pub struct ErrorEvent {
    error: ManagedGroupError,
}

impl ErrorEvent {
    pub(crate) fn new(error: ManagedGroupError) -> Self {
        Self { error }
    }

    /// Get a reference to the event's error.
    pub fn error(&self) -> &ManagedGroupError {
        &self.error
    }
}

// Helper structs

/// This enum lists the 4 different variants of a removal, depending on who the
/// remover and who the leaver is.
#[derive(Debug, PartialEq, Clone)]
pub enum Removal {
    ///  We previously issued a RemoveProposal for ourselves and this was now
    /// committed by someone else
    WeLeft,
    /// Another member issued a RemoveProposal for itself that was now committed
    TheyLeft(Credential),
    /// Another member issued a RemoveProposal for ourselves that was now
    /// committed
    WeWereRemovedBy(Credential),
    /// Member A issued a RemoveProposal for member B that was now committed
    TheyWereRemovedBy(Credential, Credential),
}

impl Removal {
    pub(crate) fn new(
        own_credential: Credential,
        remover_credential: Credential,
        leaver_credential: Credential,
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
            Self::TheyWereRemovedBy(leaver_credential, remover_credential)
        }
    }
}
