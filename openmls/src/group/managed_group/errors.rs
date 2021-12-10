//! # MLS Managed Group errors
//!
//! `WelcomeError`, `StageCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::config::ConfigError;
use crate::credentials::CredentialError;
use crate::error::ErrorString;
use crate::framing::MlsCiphertextError;
use crate::group::{CreateCommitError, ExporterError, MlsGroupError, StageCommitError};
use crate::prelude::ValidationError;
use crate::treesync::TreeSyncError;
use openmls_traits::types::CryptoError;
use tls_codec::Error as TlsCodecError;

implement_error! {
    pub enum ManagedGroupError {
        Simple {
            NoMatchingCredentialBundle = "Couldn't find a `CredentialBundle` in the `KeyStore` that matches the one in my leaf.",
            NoMatchingKeyPackageBundle = "Couldn't find a `KeyPackageBundle` in the `KeyStore` that matches the given `KeyPackage` hash.",
            PoisonedCredentialBundle = "Tried to access a poisoned `CredentialBundle`. See [`PoisonError`](`std::sync::PoisonError`) for details.",
            NoSignatureKey = "No signature key was available to verify the message signature.",
            KeyStoreError = "Error performing key store operation.",
        }
        Complex {
            LibraryError(ErrorString) =
                "An internal library error occurred. Additional detail is provided.",
            Config(ConfigError) =
                "See [`ConfigError`](`crate::config::ConfigError`) for details",
            Group(MlsGroupError) =
                "See [`MlsGroupError`](`crate::group::MlsGroupError`) for details",
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
            TreeSyncError(TreeSyncError) = "See [`TreeSyncError`](`crate::treesync::TreeSyncError`) for details",
            ValidationError(ValidationError) = "See [`ValidationError`](`crate::framing::ValidationError`) for details",
            TlsCodecError(TlsCodecError) = "An error occured during TLS encoding/decoding.",
            CryptoError(CryptoError) =
                "See [`CryptoError`](openmls_traits::types::CryptoError) for details.",
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
            GroupError(MlsGroupError) =
                "See [`MlsGroupError`](`crate::group::MlsGroupError`) for details",
        }
    }
}
