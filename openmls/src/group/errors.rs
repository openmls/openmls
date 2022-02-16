//! # MLS CoreGroup errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::{
    error::LibraryError,
    extensions::errors::ExtensionError,
    framing::errors::{MessageDecryptionError, SenderError},
    key_packages::KeyPackageError,
    schedule::PskError,
    treesync::errors::*,
};
use thiserror::Error;

// === Public errors ===

/// Welcome error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum WelcomeError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(
        "Ciphersuites in the Welcome message and the corresponding key package bundle don't match."
    )]
    CiphersuiteMismatch,
    #[error("No joiner secret found in the Welcome message.")]
    JoinerSecretNotFound,
    #[error("No ratchet tree available to build initial tree after receiving a Welcome message.")]
    MissingRatchetTree,
    #[error("The computed confirmation tag does not match the expected one.")]
    ConfirmationTagMismatch,
    #[error("The signature on the GroupInfo is not valid.")]
    InvalidGroupInfoSignature,
    #[error("Unable to decrypt the GroupInfo.")]
    GroupInfoDecryptionFailure,
    #[error("We don't support the version of the group we are trying to join.")]
    UnsupportedMlsVersion,
    #[error("We don't support the ciphersuite of the group we are trying to join.")]
    UnsupportedCiphersuite,
    #[error("We don't support all capabilities of the group.")]
    UnsupportedCapability,
    #[error("Sender not found in tree.")]
    UnknownSender,
    #[error("Malformed Welcome message.")]
    MalformedWelcomeMessage,
    #[error("Could not decrypt the Welcome message.")]
    UnableToDecrypt,
    #[error("Unsupported extensions found in the KeyPackage of another member.")]
    UnsupportedExtensions,
    #[error("A duplicate ratchet tree was found.")]
    DuplicateRatchetTreeExtension,
    #[error("More than 2^16 PSKs were provided.")]
    PskTooManyKeys,
    #[error("The PSK could not be found in the key store.")]
    PskNotFound,
    #[error("No matching KeyPackageBundle was found in the key store.")]
    NoMatchingKeyPackageBundle,
    #[error("Failed to delete the KeyPackageBundle from the key store.")]
    KeyStoreDeletionError,
    /// This error indicates the public tree is invalid. See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
}

/// External Commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExternalCommitError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("No ratchet tree available to build initial tree.")]
    MissingRatchetTree,
    #[error("The computed tree hash does not match the one in the GroupInfo.")]
    TreeHashMismatch,
    #[error("We don't support the version of the group we are trying to join.")]
    UnsupportedMlsVersion,
    #[error("We don't support the ciphersuite of the group we are trying to join.")]
    UnsupportedCiphersuite,
    #[error("Sender not found in tree.")]
    UnknownSender,
    #[error("The signature over the given public group state is invalid.")]
    InvalidPublicGroupStateSignature,
    #[error("A duplicate ratchet tree was found.")]
    DuplicateRatchetTreeExtension,
    #[error("Error creating external commit.")]
    CommitError,
    /// This error indicates the public tree is invalid. See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
}

/// Stage Commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum StageCommitError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The epoch of the group context and MlsPlaintext didn't match.")]
    EpochMismatch,
    #[error("The Commit was created by this client.")]
    OwnCommit,
    #[error("stage_commit was called with an MlsPlaintext that is not a Commit.")]
    WrongPlaintextContentType,
    #[error("Unable to verify the key package signature.")]
    PathKeyPackageVerificationFailure,
    #[error("Unable to determine commit path.")]
    RequiredPathNotFound,
    #[error("The confirmation Tag is missing.")]
    ConfirmationTagMissing,
    #[error("The confirmation tag is invalid.")]
    ConfirmationTagMismatch,
    #[error("The committer can't remove themselves.")]
    AttemptedSelfRemoval,
    #[error("The proposal queue is missing a proposal for the commit.")]
    MissingProposal,
    #[error("Missing own key to apply proposal.")]
    OwnKeyNotFound,
    #[error("External Committer used the wrong index.")]
    InconsistentSenderIndex,
    #[error("The sender is of type preconfigured, which is not valid.")]
    SenderTypePreconfigured,
    #[error("Too many new members: the tree is full.")]
    TooManyNewMembers,
    #[error(transparent)]
    ProposalValidationError(#[from] ProposalValidationError),
    #[error(transparent)]
    PskError(#[from] PskError),
    #[error(transparent)]
    ExternalCommitValidation(#[from] ExternalCommitValidationError),
    #[error(transparent)]
    UpdatePathError(#[from] ApplyUpdatePathError),
}

/// Create commit error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateCommitError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Missing own key to apply proposal.")]
    OwnKeyNotFound,
    #[error("The Commit tried to remove self from the group. This is not possible.")]
    CannotRemoveSelf,
    #[error("The proposal queue is missing a proposal for the commit.")]
    MissingProposal,
    #[error("A proposal has the wrong sender type.")]
    WrongProposalSenderType,
    #[error(transparent)]
    PskError(#[from] PskError),
    #[error(transparent)]
    ProposalValidationError(#[from] ProposalValidationError),
}

#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CreateAddProposalError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The KeyPackage does not support all required extensions.")]
    UnsupportedExtensions,
}

/// Validation error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ValidationError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Message group ID differs from the group's group ID.")]
    WrongGroupId,
    #[error("Message epoch differs from the group's epoch.")]
    WrongEpoch,
    #[error(
        "The MlsPlaintext message is not a Commit despite the sender begin of type NewMember."
    )]
    NotACommit,
    #[error("The Commit doesn't have a path despite the sender being of type NewMember.")]
    NoPath,
    #[error("The MlsPlaintext contains an application message but was not encrypted.")]
    UnencryptedApplicationMessage,
    #[error("Sender is not part of the group.")]
    UnknownMember,
    #[error("Membership tag is missing.")]
    MissingMembershipTag,
    #[error("Membership tag is invalid.")]
    InvalidMembershipTag,
    #[error("The confirmation tag is missing.")]
    MissingConfirmationTag,
    #[error("Wrong wire format.")]
    WrongWireFormat,
    #[error("Verifying the signature failed.")]
    InvalidSignature,
    #[error("An application message was sent from an external sender.")]
    NonMemberApplicationMessage,
    /// Could not decrypt the message
    #[error(transparent)]
    UnableToDecrypt(#[from] MessageDecryptionError),
}

/// Proposal validation error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposalValidationError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The sender could not be matched to a member of the group.")]
    UnknownMember,
    #[error("Found two add proposals with the same identity.")]
    DuplicateIdentityAddProposal,
    #[error("Found two add proposals with the same signature key.")]
    DuplicateSignatureKeyAddProposal,
    #[error("Found two add proposals with the same HPKE public key.")]
    DuplicatePublicKeyAddProposal,
    #[error("Identity of the add proposal already existed in tree.")]
    ExistingIdentityAddProposal,
    #[error("Signature key of the add proposal already existed in tree.")]
    ExistingSignatureKeyAddProposal,
    #[error("HPKE public key of the add proposal already existed in tree.")]
    ExistingPublicKeyAddProposal,
    #[error("The identity of the update proposal did not match the existing identity.")]
    UpdateProposalIdentityMismatch,
    #[error("Signature key of the update proposal already existed in tree.")]
    ExistingSignatureKeyUpdateProposal,
    #[error("HPKE public key of the update proposal already existed in tree.")]
    ExistingPublicKeyUpdateProposal,
    #[error("Duplicate remove proposals for the same member.")]
    DuplicateMemberRemoval,
    #[error("The remove proposal referenced a non-existing member.")]
    UnknownMemberRemoval,
    #[error("Found an update from a non-member.")]
    UpdateFromNonMember,
    #[error("The Commit includes update proposals from the committer.")]
    CommitterIncludedOwnUpdate,
}

/// External Commit validaton error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExternalCommitValidationError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("No ExternalInit proposal found.")]
    NoExternalInitProposals,
    #[error("Multiple ExternalInit proposal found.")]
    MultipleExternalInitProposals,
    #[error("Found inline Add or Update proposals.")]
    InvalidInlineProposals,
    // TODO #803: this seems unused
    #[error("Found multiple inline Remove proposals.")]
    MultipleRemoveProposals,
    #[error("Remove proposal targets the wrong group member.")]
    InvalidRemoveProposal,
    #[error("Found an ExternalInit proposal among the referenced proposals.")]
    ReferencedExternalInitProposal,
    // TODO #803: this seems unused
    #[error("External Commit has to contain a path.")]
    NoPath,
    #[error("The remove proposal referenced a non-existing member.")]
    UnknownMemberRemoval,
}

// === Crate errors ===

/// Exporter error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ExporterError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The requested key length is not supported (too large).")]
    KeyLengthTooLong,
}

/// Proposal queue error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ProposalQueueError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Not all proposals in the Commit were found locally.")]
    ProposalNotFound,
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

/// Errors that can arise when creating a [`ProposalQueue`] from committed
/// proposals.
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum FromCommittedProposalsError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Not all proposals in the Commit were found locally.")]
    ProposalNotFound,
    #[error("The sender of a Commit tried to remove themselves.")]
    SelfRemoval,
}

/// Creation proposal queue error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CreationProposalQueueError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

// Apply proposals error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum ApplyProposalsError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Own KeyPackageBundle was not found in the key store.")]
    MissingKeyPackageBundle,
}

// Core group build error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CoreGroupBuildError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Unsupported proposal type in required capabilities.")]
    UnsupportedProposalType,
    #[error("Unsupported extension type in required capabilities.")]
    UnsupportedExtensionType,
    #[error(transparent)]
    PskError(#[from] PskError),
}

// CoreGroup parse message error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CoreGroupParseMessageError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    //#[error(transparent)]
    //FramingValidationError(#[from] FramingValidationError),
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
}

/// Create group context ext proposal error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CreateGroupContextExtProposalError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(transparent)]
    KeyPackage(#[from] KeyPackageError),
    #[error(transparent)]
    Extension(#[from] ExtensionError),
}
