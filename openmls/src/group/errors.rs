//! # MLS group errors
//!
//! This module contains errors that originate at lower levels and are partially re-exported in errors thrown by functions of the `MlsGroup` API.

use crate::{
    error::LibraryError,
    extensions::errors::ExtensionError,
    framing::errors::{MessageDecryptionError, SenderError},
    key_packages::errors::KeyPackageExtensionSupportError,
    schedule::errors::PskError,
    treesync::errors::*,
};
use thiserror::Error;

// === Public errors ===

pub use super::mls_group::errors::*;

/// Welcome error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum WelcomeError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Ciphersuites in Welcome and key package bundle don't match.
    #[error("Ciphersuites in Welcome and key package bundle don't match.")]
    CiphersuiteMismatch,
    /// No joiner secret found in the Welcome message.
    #[error("No joiner secret found in the Welcome message.")]
    JoinerSecretNotFound,
    /// No ratchet tree available to build initial tree after receiving a Welcome message.
    #[error("No ratchet tree available to build initial tree after receiving a Welcome message.")]
    MissingRatchetTree,
    /// The computed confirmation tag does not match the expected one.
    #[error("The computed confirmation tag does not match the expected one.")]
    ConfirmationTagMismatch,
    /// The signature on the GroupInfo is not valid.
    #[error("The signature on the GroupInfo is not valid.")]
    InvalidGroupInfoSignature,
    /// Unable to decrypt the GroupInfo.
    #[error("Unable to decrypt the GroupInfo.")]
    GroupInfoDecryptionFailure,
    /// We don't support the version of the group we are trying to join.
    #[error("We don't support the version of the group we are trying to join.")]
    UnsupportedMlsVersion,
    /// We don't support all capabilities of the group.
    #[error("We don't support all capabilities of the group.")]
    UnsupportedCapability,
    /// Sender not found in tree.
    #[error("Sender not found in tree.")]
    UnknownSender,
    /// Malformed Welcome message.
    #[error("Malformed Welcome message.")]
    MalformedWelcomeMessage,
    /// Could not decrypt the Welcome message.
    #[error("Could not decrypt the Welcome message.")]
    UnableToDecrypt,
    /// Unsupported extensions found in the KeyPackage of another member.
    #[error("Unsupported extensions found in the KeyPackage of another member.")]
    UnsupportedExtensions,
    /// A duplicate ratchet tree was found.
    #[error("A duplicate ratchet tree was found.")]
    DuplicateRatchetTreeExtension,
    /// More than 2^16 PSKs were provided.
    #[error("More than 2^16 PSKs were provided.")]
    PskTooManyKeys,
    /// The PSK could not be found in the key store.
    #[error("The PSK could not be found in the key store.")]
    PskNotFound,
    /// No matching KeyPackageBundle was found in the key store.
    #[error("No matching KeyPackageBundle was found in the key store.")]
    NoMatchingKeyPackageBundle,
    /// Failed to delete the KeyPackageBundle from the key store.
    #[error("Failed to delete the KeyPackageBundle from the key store.")]
    KeyStoreDeletionError,
    /// This error indicates the public tree is invalid. See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
}

/// External Commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExternalCommitError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No ratchet tree available to build initial tree.
    #[error("No ratchet tree available to build initial tree.")]
    MissingRatchetTree,
    /// The computed tree hash does not match the one in the GroupInfo.
    #[error("The computed tree hash does not match the one in the GroupInfo.")]
    TreeHashMismatch,
    /// We don't support the version of the group we are trying to join.
    #[error("We don't support the version of the group we are trying to join.")]
    UnsupportedMlsVersion,
    /// We don't support the ciphersuite of the group we are trying to join.
    #[error("We don't support the ciphersuite of the group we are trying to join.")]
    UnsupportedCiphersuite,
    /// Sender not found in tree.
    #[error("Sender not found in tree.")]
    UnknownSender,
    /// The signature over the given public group state is invalid.
    #[error("The signature over the given public group state is invalid.")]
    InvalidPublicGroupStateSignature,
    /// A duplicate ratchet tree was found.
    #[error("A duplicate ratchet tree was found.")]
    DuplicateRatchetTreeExtension,
    /// Error creating external commit.
    #[error("Error creating external commit.")]
    CommitError,
    /// This error indicates the public tree is invalid. See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
}

/// Stage Commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum StageCommitError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The epoch of the group context and MlsPlaintext didn't match.
    #[error("The epoch of the group context and MlsPlaintext didn't match.")]
    EpochMismatch,
    /// The Commit was created by this client.
    #[error("The Commit was created by this client.")]
    OwnCommit,
    /// stage_commit was called with an MlsPlaintext that is not a Commit.
    #[error("stage_commit was called with an MlsPlaintext that is not a Commit.")]
    WrongPlaintextContentType,
    /// Unable to verify the key package signature.
    #[error("Unable to verify the key package signature.")]
    PathKeyPackageVerificationFailure,
    /// Unable to determine commit path.
    #[error("Unable to determine commit path.")]
    RequiredPathNotFound,
    /// The confirmation Tag is missing.
    #[error("The confirmation Tag is missing.")]
    ConfirmationTagMissing,
    /// The confirmation tag is invalid.
    #[error("The confirmation tag is invalid.")]
    ConfirmationTagMismatch,
    /// The committer can't remove themselves.
    #[error("The committer can't remove themselves.")]
    AttemptedSelfRemoval,
    /// The proposal queue is missing a proposal for the commit.
    #[error("The proposal queue is missing a proposal for the commit.")]
    MissingProposal,
    /// Missing own key to apply proposal.
    #[error("Missing own key to apply proposal.")]
    OwnKeyNotFound,
    /// External Committer used the wrong index.
    #[error("External Committer used the wrong index.")]
    InconsistentSenderIndex,
    /// The sender is of type preconfigured, which is not valid.
    #[error("The sender is of type preconfigured, which is not valid.")]
    SenderTypePreconfigured,
    /// Too many new members: the tree is full.
    #[error("Too many new members: the tree is full.")]
    TooManyNewMembers,
    /// See [`ProposalValidationError`] for more details.
    #[error(transparent)]
    ProposalValidationError(#[from] ProposalValidationError),
    /// See [`PskError`] for more details.
    #[error(transparent)]
    PskError(#[from] PskError),
    /// See [`ExternalCommitValidationError`] for more details.
    #[error(transparent)]
    ExternalCommitValidation(#[from] ExternalCommitValidationError),
    /// See [`ApplyUpdatePathError`] for more details.
    #[error(transparent)]
    UpdatePathError(#[from] ApplyUpdatePathError),
}

/// Create commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateCommitError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Missing own key to apply proposal.
    #[error("Missing own key to apply proposal.")]
    OwnKeyNotFound,
    /// The Commit tried to remove self from the group. This is not possible.
    #[error("The Commit tried to remove self from the group. This is not possible.")]
    CannotRemoveSelf,
    /// The proposal queue is missing a proposal for the commit.
    #[error("The proposal queue is missing a proposal for the commit.")]
    MissingProposal,
    /// A proposal has the wrong sender type.
    #[error("A proposal has the wrong sender type.")]
    WrongProposalSenderType,
    /// See [`PskError`] for more details.
    #[error(transparent)]
    PskError(#[from] PskError),
    /// See [`ProposalValidationError`] for more details.
    #[error(transparent)]
    ProposalValidationError(#[from] ProposalValidationError),
}

/// Validation error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ValidationError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Message group ID differs from the group's group ID.
    #[error("Message group ID differs from the group's group ID.")]
    WrongGroupId,
    /// Message epoch differs from the group's epoch.
    #[error("Message epoch differs from the group's epoch.")]
    WrongEpoch,
    /// The MlsPlaintext is not a Commit despite the sender begin of type NewMember.
    #[error("The MlsPlaintext is not a Commit despite the sender begin of type NewMember.")]
    NotACommit,
    /// The Commit doesn't have a path despite the sender being of type NewMember.
    #[error("The Commit doesn't have a path despite the sender being of type NewMember.")]
    NoPath,
    /// The MlsPlaintext contains an application message but was not encrypted.
    #[error("The MlsPlaintext contains an application message but was not encrypted.")]
    UnencryptedApplicationMessage,
    /// Sender is not part of the group.
    #[error("Sender is not part of the group.")]
    UnknownMember,
    /// Membership tag is missing.
    #[error("Membership tag is missing.")]
    MissingMembershipTag,
    /// Membership tag is invalid.
    #[error("Membership tag is invalid.")]
    InvalidMembershipTag,
    /// The confirmation tag is missing.
    #[error("The confirmation tag is missing.")]
    MissingConfirmationTag,
    /// Wrong wire format.
    #[error("Wrong wire format.")]
    WrongWireFormat,
    /// Verifying the signature failed.
    #[error("Verifying the signature failed.")]
    InvalidSignature,
    /// An application message was sent from an external sender.
    #[error("An application message was sent from an external sender.")]
    NonMemberApplicationMessage,
    /// Could not decrypt the message
    #[error(transparent)]
    UnableToDecrypt(#[from] MessageDecryptionError),
}

/// Proposal validation error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposalValidationError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The sender could not be matched to a member of the group.
    #[error("The sender could not be matched to a member of the group.")]
    UnknownMember,
    /// Found two add proposals with the same identity.
    #[error("Found two add proposals with the same identity.")]
    DuplicateIdentityAddProposal,
    /// Found two add proposals with the same signature key.
    #[error("Found two add proposals with the same signature key.")]
    DuplicateSignatureKeyAddProposal,
    /// Found two add proposals with the same HPKE public key.
    #[error("Found two add proposals with the same HPKE public key.")]
    DuplicatePublicKeyAddProposal,
    /// Identity of the add proposal already existed in tree.
    #[error("Identity of the add proposal already existed in tree.")]
    ExistingIdentityAddProposal,
    /// Signature key of the add proposal already existed in tree.
    #[error("Signature key of the add proposal already existed in tree.")]
    ExistingSignatureKeyAddProposal,
    /// HPKE public key of the add proposal already existed in tree.
    #[error("HPKE public key of the add proposal already existed in tree.")]
    ExistingPublicKeyAddProposal,
    /// The identity of the update proposal did not match the existing identity.
    #[error("The identity of the update proposal did not match the existing identity.")]
    UpdateProposalIdentityMismatch,
    /// Signature key of the update proposal already existed in tree.
    #[error("Signature key of the update proposal already existed in tree.")]
    ExistingSignatureKeyUpdateProposal,
    /// HPKE public key of the update proposal already existed in tree.
    #[error("HPKE public key of the update proposal already existed in tree.")]
    ExistingPublicKeyUpdateProposal,
    /// Duplicate remove proposals for the same member.
    #[error("Duplicate remove proposals for the same member.")]
    DuplicateMemberRemoval,
    /// The remove proposal referenced a non-existing member.
    #[error("The remove proposal referenced a non-existing member.")]
    UnknownMemberRemoval,
    /// Found an update from a non-member.
    #[error("Found an update from a non-member.")]
    UpdateFromNonMember,
    /// The Commit includes update proposals from the committer.
    #[error("The Commit includes update proposals from the committer.")]
    CommitterIncludedOwnUpdate,
    /// The capabilities of the add proposal are insufficient for this group.
    #[error("The capabilities of the add proposal are insufficient for this group.")]
    InsufficientCapabilities,
}

/// External Commit validaton error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExternalCommitValidationError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No ExternalInit proposal found.
    #[error("No ExternalInit proposal found.")]
    NoExternalInitProposals,
    /// Multiple ExternalInit proposal found.
    #[error("Multiple ExternalInit proposal found.")]
    MultipleExternalInitProposals,
    /// Found inline Add or Update proposals.
    #[error("Found inline Add or Update proposals.")]
    InvalidInlineProposals,
    // TODO #803: this seems unused
    /// Found multiple inline Remove proposals.
    #[error("Found multiple inline Remove proposals.")]
    MultipleRemoveProposals,
    /// Remove proposal targets the wrong group member.
    #[error("Remove proposal targets the wrong group member.")]
    InvalidRemoveProposal,
    /// Found an ExternalInit proposal among the referenced proposals.
    #[error("Found an ExternalInit proposal among the referenced proposals.")]
    ReferencedExternalInitProposal,
    // TODO #803: this seems unused
    /// External Commit has to contain a path.
    #[error("External Commit has to contain a path.")]
    NoPath,
    /// The remove proposal referenced a non-existing member.
    #[error("The remove proposal referenced a non-existing member.")]
    UnknownMemberRemoval,
}

// === Crate errors ===

/// Create add proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CreateAddProposalError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The KeyPackage does not support all required extensions.
    #[error("The KeyPackage does not support all required extensions.")]
    UnsupportedExtensions,
}

/// Exporter error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ExporterError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The requested key length is not supported (too large).")]
    KeyLengthTooLong,
}

/// Proposal queue error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ProposalQueueError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Not all proposals in the Commit were found locally.
    #[error("Not all proposals in the Commit were found locally.")]
    ProposalNotFound,
    /// See [`SenderError`] for more details.
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

/// Errors that can arise when creating a [`ProposalQueue`] from committed
/// proposals.
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum FromCommittedProposalsError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Not all proposals in the Commit were found locally.
    #[error("Not all proposals in the Commit were found locally.")]
    ProposalNotFound,
    /// The sender of a Commit tried to remove themselves.
    #[error("The sender of a Commit tried to remove themselves.")]
    SelfRemoval,
}

/// Creation proposal queue error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CreationProposalQueueError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`SenderError`] for more details.
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

// Apply proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ApplyProposalsError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Own KeyPackageBundle was not found in the key store.
    #[error("Own KeyPackageBundle was not found in the key store.")]
    MissingKeyPackageBundle,
}

// Core group build error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CoreGroupBuildError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Unsupported proposal type in required capabilities.
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
    /// Unsupported extension type in required capabilities.
    #[error("Unsupported extension type in required capabilities.")]
    UnsupportedExtensionType,
    /// See [`PskError`] for more details.
    #[error(transparent)]
    PskError(#[from] PskError),
}

// CoreGroup parse message error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CoreGroupParseMessageError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    //#[error(transparent)]
    //FramingValidationError(#[from] FramingValidationError),
    /// See [`ValidationError`] for more details.
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
}

/// Create group context ext proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CreateGroupContextExtProposalError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`KeyPackageExtensionSupportError`] for more details.
    #[error(transparent)]
    KeyPackageExtensionSupport(#[from] KeyPackageExtensionSupportError),
    /// See [`ExtensionError`] for more details.
    #[error(transparent)]
    Extension(#[from] ExtensionError),
}
