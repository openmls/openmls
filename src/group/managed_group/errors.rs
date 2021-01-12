//! # MLS Managed Group errors
//!
//! `WelcomeError`, `ApplyCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::codec::CodecError;
use crate::config::ConfigError;
use crate::error::{ErrorPayload, ErrorString};
use crate::group::{ApplyCommitError, CreateCommitError, ExporterError, GroupError};

implement_error! {
    pub enum ManagedGroupError {
        LibraryError(ErrorString) =
            "An internal library error occurred. Additional detail is provided.",
        Codec(CodecError) =
            "See [`CodecError`](`crate::codec::CodecError`) for details",
        Config(ConfigError) =
            "See [`ConfigError`](`crate::config::ConfigError`) for details",
        Group(GroupError) =
            "See [`GroupError`](`crate::group::GroupError`) for details",
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
        InvalidCiphertext(ErrorPayload) =
            "An invalid ciphertext was provided. The error returns the associated data of the ciphertext.",
        CommitWithInvalidProposals(ErrorString) =
            "A commit contained an invalid proposal. Additional detail is provided.",
        CommitError(ApplyCommitError) =
            "See [`ApplyCommitError`](`crate::group::ApplyCommitError`) for details",
        GroupError(GroupError) =
            "See [`GroupError`](`crate::group::GroupError`) for details",
    }
}
