//! # MLS Group errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::ciphersuite::CryptoError;
use crate::config::ConfigError;
use crate::credentials::CredentialError;
use crate::framing::errors::{MlsCiphertextError, MlsPlaintextError, VerificationError};
use crate::messages::errors::ProposalQueueError;
use crate::schedule::errors::{KeyScheduleError, PskSecretError};
use crate::tree::{treemath::TreeMathError, ParentHashError, TreeError};
use crate::treesync::{diff::TreeSyncDiffError, treekem::TreeKemError, TreeSyncError};
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum MlsGroupError {
        Simple {
            InitSecretNotFound =
                "Missing init secret when creating commit.",
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
                "See [`CreationProposalQueueError`](`crate::messages::errors::CreationProposalQueueError`) for details.",
            CodecError(TlsCodecError) =
                "Tls (de)serialization occurred.",
            KeyScheduleError(KeyScheduleError) =
                "An error occurred in the key schedule.",
            MathError(TreeMathError) =
                "An error occurred during a tree math operation.",
            PskError(PskError) =
                "A PSK error occured.",
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
            UnknownSender =
                "Sender not found in tree.",
            }
        Complex {
            ConfigError(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details.",
            InvalidRatchetTree(TreeError) =
                "Invalid ratchet tree in Welcome message.",
            ParentHashMismatch(ParentHashError) =
                "The parent hash verification failed.",
            GroupSecretsDecryptionFailure(CryptoError) =
                "Unable to decrypt the EncryptedGroupSecrets.",
            CodecError(TlsCodecError) =
                "Tls (de)serialization error occurred.",
            KeyScheduleError(KeyScheduleError) =
                "An error occurred in the key schedule.",
            PskError(PskError) =
                "A PSK error occured.",
            TreeSyncError(TreeSyncError) =
                "An error occurred while importing the new tree.",
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
            TlsCodecError(TlsCodecError) = "Error serializing",
        }
    }
}

implement_error! {
    pub enum StagedProposalQueueError {
        Simple {
            ProposalNotFound = "Not all proposals in the Commit were found locally.",
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
            ArchitectureError = "Couldn't fit a `u32` into a `usize`.",
        }
        Complex {
            NotAProposal(StagedProposalError) = "The given MLS Plaintext was not a Proposal.",
        }
    }
}
