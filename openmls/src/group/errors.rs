//! # MLS CoreGroup errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::{
    config::ConfigError,
    credentials::CredentialError,
    error::LibraryError,
    extensions::errors::ExtensionError,
    framing::errors::{MessageDecryptionError, SenderError, ValidationError},
    key_packages::KeyPackageError,
    schedule::PskError,
    treesync::errors::*,
};
use openmls_traits::types::CryptoError;
use thiserror::Error;
use tls_codec::Error as TlsCodecError;

// === Public errors ===

/// CoreGroup error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CoreGroupError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Couldn't find KeyPackageBundle corresponding to own update proposal.")]
    MissingKeyPackageBundle,
    #[error("No signature key was found.")]
    NoSignatureKey,
    #[error(transparent)]
    MlsCiphertextError(#[from] MessageDecryptionError),
    #[error(transparent)]
    WelcomeError(#[from] WelcomeError),
    #[error(transparent)]
    ExternalCommitError(#[from] ExternalCommitError),
    #[error(transparent)]
    StageCommitError(#[from] StageCommitError),
    #[error(transparent)]
    CreateCommitError(#[from] CreateCommitError),
    #[error(transparent)]
    ConfigError(#[from] ConfigError),
    #[error(transparent)]
    ExporterError(#[from] ExporterError),
    #[error(transparent)]
    ProposalQueueError(#[from] ProposalQueueError),
    #[error(transparent)]
    CodecError(#[from] TlsCodecError),
    #[error(transparent)]
    PskSecretError(#[from] PskError),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error(transparent)]
    TreeSyncError(#[from] TreeSyncError),
    #[error(transparent)]
    TreeSyncDiffError(#[from] TreeSyncDiffError),
    #[error(transparent)]
    TreeKemError(#[from] TreeKemError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
    #[error(transparent)]
    ExtensionError(#[from] ExtensionError),
    #[error(transparent)]
    ValidationError(#[from] ValidationError),
    #[error(transparent)]
    FramingValidationError(#[from] FramingValidationError),
    #[error(transparent)]
    ProposalValidationError(#[from] ProposalValidationError),
    #[error(transparent)]
    ExternalCommitValidationError(#[from] ExternalCommitValidationError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

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
    WrongProposalSender,
    #[error(transparent)]
    PskError(#[from] PskError),
    #[error(transparent)]
    ProposalValidationError(#[from] ProposalValidationError),
}

#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreateAddProposalError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The KeyPackage does not support all required extensions.")]
    UnsupportedExtensions,
}

// === Crate errors ===

/// Exporter error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ExporterError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The requested key length is not supported (too large).")]
    KeyLengthTooLong,
}

/// Proposal queue error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ProposalQueueError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Not all proposals in the Commit were found locally.")]
    ProposalNotFound,
    #[error("The sender of a Commit tried to remove themselves.")]
    SelfRemoval,
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

/// Creation proposal queue error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum CreationProposalQueueError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(transparent)]
    SenderError(#[from] SenderError),
}

/// Framing validaton error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum FramingValidationError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Message group ID differs from the group's group ID.")]
    WrongGroupId,
    #[error("Message epoch differs from the group's epoch.")]
    WrongEpoch,
    #[error("The sender could not be matched to a member of the group.")]
    UnknownMember,
    #[error("Application messages must always be encrypted.")]
    UnencryptedApplicationMessage,
    #[error("An application message was sent from an external sender.")]
    NonMemberApplicationMessage,
    #[error("Membership tag is missing.")]
    MissingMembershipTag,
    #[error("Confirmation tag is missing.")]
    MissingConfirmationTag,
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
