//! # MLS CoreGroup errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::{
    config::ConfigError,
    credentials::CredentialError,
    error::LibraryError,
    extensions::errors::ExtensionError,
    framing::errors::{
        MlsCiphertextError, MlsPlaintextError, SenderError, ValidationError, VerificationError,
    },
    key_packages::KeyPackageError,
    messages::errors::ProposalError,
    schedule::{KeyScheduleError, PskSecretError},
    tree::{ParentHashError, TreeError},
    treesync::{diff::TreeSyncDiffError, treekem::TreeKemError, TreeSyncError},
};
use openmls_traits::types::CryptoError;
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum CoreGroupError {
        Simple {
            MissingKeyPackageBundle =
                "Couldn't find KeyPackageBundle corresponding to own update proposal.",
            NoSignatureKey = "No signature key was found.",
            OwnCommitError = "Can't process a commit created by the owner of the group. Please merge the [`StagedCommit`] returned by `create_commit` instead.",
        }
        Complex {
            LibraryError(LibraryError) = "A LibraryError occurred.",
            MlsCiphertextError(MlsCiphertextError) =
                "See [`MlsCiphertextError`](`crate::framing::errors::MlsCiphertextError`) for details.",
            MlsPlaintextError(MlsPlaintextError) =
                "See [`MlsPlaintextError`](`crate::framing::errors::MlsPlaintextError`) for details.",
            WelcomeError(WelcomeError) =
                "See [`WelcomeError`](`WelcomeError`) for details.",
            ExternalCommitError(ExternalCommitError) =
                "See [`Externaallow(lint)`](`ExternalInitError`) for details.",
            StageCommitError(StageCommitError) =
                "See [`StageCommitError`](`StageCommitError`) for details.",
            CreateCommitError(CreateCommitError) =
                "See [`CreateCommitError`](`CreateCommitError`) for details.",
            ConfigError(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details.",
            ExporterError(ExporterError) =
                "See [`ExporterError`](`ExporterError`) for details.",
            ProposalQueueError(ProposalQueueError) =
                "See [`ProposalQueueError`](`crate::messages::errors::ProposalQueueError`) for details.",
            CodecError(TlsCodecError) =
                "TLS (de)serialization error occurred.",
            KeyScheduleError(KeyScheduleError) =
                "An error occurred in the key schedule.",
            PskSecretError(PskSecretError) =
                "A PskSecret error occurred.",
            CredentialError(CredentialError) =
                "See [`CredentialError`](crate::credentials::CredentialError) for details.",
            TreeError(TreeError) =
                "See [`TreeError`](crate::tree::TreeError) for details.",
            TreeSyncError(TreeSyncError) =
                "See [`TreeSyncError`](crate::treesync::TreeSyncError) for details.",
            TreeSyncDiffError(TreeSyncDiffError) =
                "See [`TreeSyncDiffError`](crate::treesync::diff::TreeSyncDiffError) for details.",
            TreeKemError(TreeKemError) =
                "See [`TreeKemError`](crate::treesync::treekem::TreeKemError) for details.",
            KeyPackageError(KeyPackageError) =
                "See [`KeyPackageError`] for details.",
            ExtensionError(ExtensionError) =
                "See [`ExtensionError`] for details.",
            ValidationError(ValidationError) =
                "See [`ValidationError`](crate::framing::ValidationError) for details.",
            FramingValidationError(FramingValidationError) =
                "See [`FramingValidationError`](crate::group::FramingValidationError) for details.",
            ProposalValidationError(ProposalValidationError) =
                "See [`ProposalValidationError`](crate::group::ProposalValidationError) for details.",
            ExternalCommitValidationError(ExternalCommitValidationError) =
                "See [`ProposalValidationError`](crate::group::ProposalValidationError) for details.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
            InterimTranscriptHashError(InterimTranscriptHashError) =
                "See [`InterimTranscriptHashError`](crate::group::InterimTranscriptHashError) for details.",
            QueuedProposalError(QueuedProposalError) =
                "See [`QueuedProposalError`](crate::group::QueuedProposalError) for details.",
            SenderError(SenderError) =
                "Sender error",
        }
    }
}

implement_error! {
    pub enum WelcomeError {
        Simple {
            CiphersuiteMismatch =
                "Ciphersuites in the Welcome message and the corresponding key package bundle don't match.",
            JoinerSecretNotFound =
                "No joiner secret found in the Welcome message.",
            MissingRatchetTree =
                "No ratchet tree available to build initial tree after receiving a Welcome message.",
            TreeHashMismatch =
                "The computed tree hash does not match the one in the GroupInfo.",
            ConfirmationTagMismatch =
                "The computed confirmation tag does not match the expected one.",
            InvalidGroupInfoSignature =
                "The signature on the GroupInfo is not valid.",
            GroupInfoDecryptionFailure =
                "Unable to decrypt the GroupInfo.",
            UnsupportedMlsVersion =
                "The Welcome message uses an unsupported MLS version.",
            MissingKeyPackage =
                "The sender key package is missing.",
            UnknownError =
                "An unknown error occurred.",
            UnknownSender =
                "Sender not found in tree.",
            LibraryError = "An unrecoverable error has occurred due to a bug in the implementation.",
            }
        Complex {
            ConfigError(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details.",
            InvalidRatchetTree(TreeError) =
                "Invalid ratchet tree in Welcome message.",
            ParentHashMismatch(ParentHashError) =
                "The parent hash verification failed.",
            CodecError(TlsCodecError) =
                "Tls (de)serialization error occurred.",
            KeyScheduleError(KeyScheduleError) =
                "An error occurred in the key schedule.",
            PskSecretError(PskSecretError) =
                "A PskSecret error occured.",
            TreeSyncError(TreeSyncError) =
                "An error occurred while importing the new tree.",
            ExtensionError(ExtensionError) =
                "See [`ExtensionError`] for details.",
            KeyPackageError(KeyPackageError) =
                "See [`KeyPackageError`] for details.",
            InterimTranscriptHashError(InterimTranscriptHashError) =
                "See [`InterimTranscriptHashError`] for details.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
            ProposalError(QueuedProposalError) =
                "See [`QueuedProposalError`] for details.",
        }
    }
}

implement_error! {
    pub enum ExternalCommitError {
        Simple {
            MissingRatchetTree =
                "No ratchet tree available to build initial tree.",
            TreeHashMismatch =
                "The computed tree hash does not match the one in the GroupInfo.",
            UnsupportedMlsVersion =
                "We don't support the version of the group we are trying to join.",
            UnknownSender =
                "Sender not found in tree.",
            InvalidPublicGroupStateSignature =
                "The signature over the given public group state is invalid.",
            LibraryError = "An unrecoverable error has occurred due to a bug in the implementation.",
            CommitError =
                "Error creating external commit.",
            }
        Complex {
            VerificationError(CredentialError) =
                "Error verifying `PublicGroupState`.",
            ConfigError(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details.",
            CodecError(TlsCodecError) =
                "Tls (de)serialization error occurred.",
            KeyScheduleError(KeyScheduleError) =
                "An error occurred in the key schedule.",
            TreeSyncError(TreeSyncError) =
                "An error occurred while importing the new tree.",
            TreeSyncDiffError(TreeSyncDiffError) =
                "An error occurred while adding our own leaf to the new tree.",
            ExtensionError(ExtensionError) =
                "See [`ExtensionError`] for details.",
            KeyPackageError(KeyPackageError) =
                "See [`KeyPackageError`] for details.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
            ProposalError(QueuedProposalError) =
                "See [`QueuedProposalError`] for details.",
        }
    }
}

implement_error! {
    pub enum StageCommitError {
        Simple {
            EpochMismatch =
                "Couldn't stage Commit. The epoch of the group context and MlsPlaintext didn't match.",
            WrongPlaintextContentType =
                "stage_commit was called with an MlsPlaintext that is not a Commit.",
            SelfRemoved =
                "Tried to stage a commit to a group we are not a part of.",
            PathKeyPackageVerificationFailure =
                "Unable to verify the key package signature.",
            NoParentHashExtension =
                "Parent hash extension is missing.",
            ParentHashMismatch =
                "Parent hash values don't match.",
            RequiredPathNotFound =
                "Unable to determine commit path.",
            ConfirmationTagMissing =
                "Confirmation Tag is missing.",
            ConfirmationTagMismatch =
                "Confirmation tag is invalid.",
            MissingOwnKeyPackage =
                "No key package provided to apply own commit.",
            MissingProposal =
                "The proposal queue is missing a proposal for the commit.",
            OwnKeyNotFound =
                "Missing own key to apply proposal.",
            InconsistentSenderIndex =
                "External Committer used the wrong index.",
            LibraryError =
                "An unrecoverable error has occurred due to a bug in the implementation.",
        }
        Complex {
            PlaintextSignatureFailure(VerificationError) =
                "MlsPlaintext signature is invalid.",
            CodecError(TlsCodecError) =
                "Tls (de)serialization error occurred.",
            KeyScheduleError(KeyScheduleError) =
                "An error occurred in the key schedule.",
        }
    }
}

implement_error! {
    pub enum CreateCommitError {
        CannotRemoveSelf =
            "The Commit tried to remove self from the group. This is not possible.",
        OwnKeyNotFound =
            "Couldn't create the commit because there's no key to apply the proposals.",
    }
}

implement_error! {
    pub enum ExporterError {
        KeyLengthTooLong =
            "The requested key length is not supported (too large).",
    }
}

implement_error! {
    pub enum QueuedProposalError {
        Simple {
            WrongContentType = "API misuse. Only proposals can end up in the proposal queue",
        }
        Complex {
            LibraryError(LibraryError) = "A LibraryError occurred.",
            ProposalError(ProposalError) = "A ProposalError occurred.",
            TlsCodecError(TlsCodecError) = "Error serializing",
        }
    }
}

implement_error! {
    pub enum ProposalQueueError {
        Simple {
            ProposalNotFound = "Not all proposals in the Commit were found locally.",
            SelfRemoval = "The sender of a Commit tried to remove themselves.",
            ArchitectureError = "Couldn't fit a `u32` into a `usize`.",
            RemovedNotFound = "Couldn't find the member to remove.",
            LibraryError = "An unrecoverable error has occurred due to a bug in the implementation.",
        }
        Complex {
            NotAProposal(QueuedProposalError) = "The given MLS Plaintext was not a Proposal.",
            SenderError(SenderError) = "Sender error",
        }
    }
}

implement_error! {
    pub enum CreationProposalQueueError {
        Simple {
            ProposalNotFound = "Not all proposals in the Commit were found locally.",
            ArchitectureError = "Couldn't fit a `u32` into a `usize`.",
        }
        Complex {
            LibraryError(LibraryError) = "A LibraryError occurred.",
            NotAProposal(QueuedProposalError) = "The given MLS Plaintext was not a Proposal.",
            SenderError(SenderError) = "Sender error",
        }
    }
}

implement_error! {
    pub enum FramingValidationError {
        WrongGroupId = "Message group ID differs from the group's group ID.",
        WrongEpoch = "Message epoch differs from the group's epoch.",
        UnknownMember = "The sender could not be matched to a member of the group.",
        UnencryptedApplicationMessage = "Application messages must always be encrypted.",
        NonMemberApplicationMessage = "An application message was sent from an external sender.",
        MissingMembershipTag = "Membership tag is missing.",
        MissingConfirmationTag = "Confirmation tag is missing.",
    }
}

implement_error! {
    pub enum ProposalValidationError {
        UnknownMember = "The sender could not be matched to a member of the group.",
        DuplicateIdentityAddProposal = "Found two add proposals with the same identity.",
        DuplicateSignatureKeyAddProposal = "Found two add proposals with the same signature key.",
        DuplicatePublicKeyAddProposal = "Found two add proposals with the same HPKE public key.",
        ExistingIdentityAddProposal = "Identity of the add proposal already existed in tree.",
        ExistingSignatureKeyAddProposal = "Signature key of the add proposal already existed in tree.",
        ExistingPublicKeyAddProposal = "HPKE public key of the add proposal already existed in tree.",
        UpdateProposalIdentityMismatch = "The identity of the update proposal did not match the existing identity.",
        ExistingSignatureKeyUpdateProposal = "Signature key of the update proposal already existed in tree.",
        ExistingPublicKeyUpdateProposal = "HPKE public key of the update proposal already existed in tree.",
        DuplicateMemberRemoval = "Duplicate remove proposals for the same member.",
        UnknownMemberRemoval = "The remove proposal referenced a non-existing member.",
    }
}

implement_error! {
    pub enum ExternalCommitValidationError {
        NoExternalInitProposals = "No ExternalInit proposal found.",
        MultipleExternalInitProposals = "Multiple ExternalInit proposal found.",
        InvalidInlineProposals = "Found inline Add or Update proposals.",
        MultipleRemoveProposals = "Found multiple inline Remove proposals.",
        InvalidRemoveProposal = "Remove proposal targets the wrong group member.",
        ReferencedExternalInitProposal = "Found an ExternalInit proposal among the referenced proposals.",
        NoPath = "External Commit has to contain a path.",
        NoCommit = "A Message sent by a sender with type NewMember can only be a Commit.",
    }
}

implement_error! {
    pub enum InterimTranscriptHashError {
        Simple {}
        Complex {
            CodecError(TlsCodecError) =
                "TLS (de)serialization error occurred.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
        }
    }
}
