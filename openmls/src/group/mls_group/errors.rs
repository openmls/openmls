//! # MLS MlsGroup errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::config::ConfigError;
use crate::credentials::CredentialError;
use crate::error::LibraryError;
use crate::framing::MlsCiphertextError;
use crate::framing::ValidationError;
use crate::group::WelcomeError;
use crate::group::{CoreGroupError, CreateCommitError, ExporterError, StageCommitError};
use crate::treesync::TreeSyncError;
use openmls_traits::types::CryptoError;
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum MlsGroupError {
        Simple {
            NoMatchingCredentialBundle = "Couldn't find a `CredentialBundle` in the `KeyStore` that matches the one in my leaf.",
            NoMatchingKeyPackageBundle = "Couldn't find a `KeyPackageBundle` in the `KeyStore` that matches the given `KeyPackage` hash.",
            PoisonedCredentialBundle = "Tried to access a poisoned `CredentialBundle`. See [`PoisonError`](`std::sync::PoisonError`) for details.",
            NoSignatureKey = "No signature key was available to verify the message signature.",
            PendingCommitError = "Can't create a new commit while another commit is still pending. Please clear or merge the pending commit before creating a new one.",
            NoPendingCommit = "There is no pending commit that can be merged.",
            ExternalCommitError = "Can't clear an external commit, as the group can't merge `Member` commits yet. If an external commit is rejected by the DS, a new external init must be performed. See the MLS spec for more information.",
            KeyStoreError = "Error performing key store operation.",
            IncompatibleWireFormat = "The incoming message's wire format was not compatible with the wire format policy for incoming messages.",
        }
        Complex {
            LibraryError(LibraryError) =
                "An internal library error occurred. Additional detail is provided.",
            Config(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details",
            Group(CoreGroupError) =
                "See [`CoreGroupError`](`crate::group::CoreGroupError`) for details",
            CreateCommit(CreateCommitError) =
                "See [`CreateCommitError`](`crate::group::CreateCommitError`) for details",
            UseAfterEviction(UseAfterEviction) =
                "See [`UseAfterEviction`](`UseAfterEviction`) for details",
            PendingProposalsExist(PendingProposalsError) =
                "See [`PendingProposalsError`](`PendingProposalsError`) for details",
            Exporter(ExporterError) =
                "See [`ExporterError`](`crate::group::ExporterError`) for details",
            EmptyInput(EmptyInputError) =
                "Empty input. Additional detail is provided.",
            InvalidMessage(InvalidMessageError) = "The message could not be processed.",
            CredentialError(CredentialError) = "See [`CredentialError`](`crate::credentials::CredentialError`) for details",
            TreeSyncError(TreeSyncError) = "An error occurred during an operation on the tree underlying the group.",
            ValidationError(ValidationError) = "See [`ValidationError`](`crate::framing::ValidationError`) for details",
            TlsCodecError(TlsCodecError) = "An error occured during TLS encoding/decoding.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
            WelcomeError(WelcomeError) = "See [`WelcomeError`] for details.",
        }
    }
}

implement_error! {
    pub enum EmptyInputError {
        AddMembers = "An empty list of KeyPackages was provided.",
        RemoveMembers = "An empty list of indexes was provided.",
    }
}

implement_error! {
    pub enum UseAfterEviction {
        Error = "Tried to use a group after being evicted from it.",
    }
}

implement_error! {
    pub enum PendingProposalsError {
        Exists = "Can't create message because a pending proposal exists.",
    }
}

implement_error! {
    pub enum InvalidMessageError {
        Simple {
            MissingMembershipTag =
                "A message without a membership tag received.",
            MembershipTagMismatch =
                "A message with an invalid membership tag was received.",
            UnknownSender =
                "Could not retrieve credential for the given sender.",
            InvalidProposal =
                "The given proposal is invalid.",
            CommitWithInvalidProposals =
                "A commit contained an invalid proposal.",
            InvalidApplicationMessage =
                "The application message is invalid.",
            WrongEpoch = "The epoch does not match the group's epoch.",
            MissingConfirmationTag = "The confirmation tag is missing in the Commit message.",
            InvalidSignature = "The message's signature is invalid.",
            WrongGroupId = "Wrong group ID.",
        }
        Complex {
            InvalidCiphertext(MlsCiphertextError) =
                "An invalid ciphertext was provided. The error returns the associated data of the ciphertext.",
            CommitError(StageCommitError) =
                "See [`StageCommitError`](`crate::group::StageCommitError`) for details",
            GroupError(CoreGroupError) =
                "See [`CoreGroupError`](`crate::group::CoreGroupError`) for details",
        }
    }
}
