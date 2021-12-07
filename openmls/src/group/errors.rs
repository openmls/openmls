//! # MLS Group errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::config::ConfigError;
use crate::credentials::CredentialError;
use crate::extensions::errors::ExtensionError;
use crate::framing::errors::{
    MlsCiphertextError, MlsPlaintextError, ValidationError, VerificationError,
};
use crate::key_packages::KeyPackageError;
use crate::messages::errors::{ProposalError, ProposalQueueError};
use crate::schedule::errors::{KeyScheduleError, PskSecretError};
use crate::tree::{treemath::TreeMathError, ParentHashError, TreeError};
use openmls_traits::types::CryptoError;
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum CoreGroupError {
        Simple {
            InitSecretNotFound =
                "Missing init secret when creating commit.",
            NoSignatureKey = "No signature key was found.",
            LibraryError = "An unrecoverable error has occurred due to a bug in the implementation.",
        }
        Complex {
            MlsCiphertextError(MlsCiphertextError) =
                "See [`MlsCiphertextError`](`crate::framing::errors::MlsCiphertextError`) for details.",
            MlsPlaintextError(MlsPlaintextError) =
                "See [`MlsPlaintextError`](`crate::framing::errors::MlsPlaintextError`) for details.",
            WelcomeError(WelcomeError) =
                "See [`WelcomeError`](`WelcomeError`) for details.",
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
            CreationProposalQueueError(CreationProposalQueueError) =
                "See [`CreationProposalQueueError`](`crate::group::errors::CreationProposalQueueError`) for details.",
            CodecError(TlsCodecError) =
                "TLS (de)serialization error occurred.",
            KeyScheduleError(KeyScheduleError) =
                "An error occurred in the key schedule.",
            MathError(TreeMathError) =
                "An error occurred during a tree math operation.",
            PskError(PskError) =
                "A PSK error occurred.",
            CredentialError(CredentialError) =
                "See [`CredentialError`](crate::credentials::CredentialError) for details.",
            TreeError(TreeError) =
                "See [`TreeError`](crate::tree::TreeError) for details.",
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
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
            InterimTranscriptHashError(InterimTranscriptHashError) =
                "See [`InterimTranscriptHashError`](crate::group::InterimTranscriptHashError) for details.",
            StagedProposalError(StagedProposalError) =
                "See [`StagedProposalError`](crate::group::StagedProposalError) for details.",
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
            DuplicateRatchetTreeExtension =
                "Found a duplicate ratchet tree extension in the Welcome message.",
            UnsupportedMlsVersion =
                "The Welcome message uses an unsupported MLS version.",
            MissingKeyPackage =
                "The sender key package is missing.",
            UnknownError =
                "An unknown error occurred.",
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
            PskError(PskError) =
                "A PSK error occured.",
            ExtensionError(ExtensionError) =
                "See [`ExtensionError`] for details.",
            KeyPackageError(KeyPackageError) =
                "See [`KeyPackageError`] for details.",
            InterimTranscriptHashError(InterimTranscriptHashError) =
                "See [`InterimTranscriptHashError`] for details.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
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
            InitSecretNotFound =
                "Missing init secret to apply proposal.",
        }
        Complex {
            PlaintextSignatureFailure(VerificationError) =
                "MlsPlaintext signature is invalid.",
            DecryptionFailure(TreeError) =
                "A matching EncryptedPathSecret failed to decrypt.",
            CodecError(TlsCodecError) =
                "Tls (de)serialization error occurred.",
            KeyScheduleError(KeyScheduleError) =
                "An error occurred in the key schedule.",
            PskError(PskError) =
                "A PSK error occurred.",
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
    pub enum PskError {
        Simple {
            NoPskFetcherProvided =
                "A PSK was needed, but no PSK fetcher function was provided.",
            PskIdNotFound =
                "No PSK was found for PSK ID.",
        }
        Complex {
            PskSecretError(PskSecretError) =
                "An error occured when concatenating the PSKs.",
        }
    }
}

implement_error! {
    pub enum StagedProposalError {
        Simple {
            WrongContentType = "API misuse. Only proposals can end up in the proposal queue",
        }
        Complex {
            ProposalError(ProposalError) = "A ProposalError occurred.",
            TlsCodecError(TlsCodecError) = "Error serializing",
        }
    }
}

implement_error! {
    pub enum StagedProposalQueueError {
        Simple {
            ProposalNotFound = "Not all proposals in the Commit were found locally.",
            SelfRemoval = "The sender of a Commit tried to remove themselves.",
        }
        Complex {
            NotAProposal(StagedProposalError) = "The given MLS Plaintext was not a Proposal.",
        }
    }
}

implement_error! {
    pub enum CreationProposalQueueError {
        Simple {
            ProposalNotFound = "Not all proposals in the Commit were found locally.",
        }
        Complex {
            NotAProposal(StagedProposalError) = "The given MLS Plaintext was not a Proposal.",
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
