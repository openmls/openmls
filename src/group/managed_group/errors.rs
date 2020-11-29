//! # MLS Managed Group errors
//!
//! `WelcomeError`, `ApplyCommitError`, `DecryptionError`, and
//! `CreateCommitError`.
//!
//! #[derive(PartialEq, Debug)]

use crate::codec::CodecError;
use crate::config::ConfigError;
use crate::group::{ApplyCommitError, CreateCommitError, GroupError};

use std::error::Error;

#[derive(PartialEq, Debug)]
pub enum ManagedGroupError {
    Unknown,
    Codec(CodecError),
    Config(ConfigError),
    Group(GroupError),
    CreateCommit(CreateCommitError),
    UseAfterEviction,
    PendingProposalsExist,
}

impl From<ConfigError> for ManagedGroupError {
    fn from(err: ConfigError) -> ManagedGroupError {
        ManagedGroupError::Config(err)
    }
}

impl From<CodecError> for ManagedGroupError {
    fn from(err: CodecError) -> ManagedGroupError {
        ManagedGroupError::Codec(err)
    }
}

impl From<GroupError> for ManagedGroupError {
    fn from(err: GroupError) -> ManagedGroupError {
        ManagedGroupError::Group(err)
    }
}

impl From<CreateCommitError> for ManagedGroupError {
    fn from(err: CreateCommitError) -> ManagedGroupError {
        ManagedGroupError::CreateCommit(err)
    }
}

#[derive(Debug)]
pub enum InvalidMessageError {
    InvalidCiphertext(Vec<u8>),
    CommitWithInvalidProposals,
    CommitError(ApplyCommitError),
}

implement_enum_display!(InvalidMessageError);

impl Error for InvalidMessageError {
    fn description(&self) -> &str {
        match self {
            Self::InvalidCiphertext(_) => "Invalid ciphertext received",
            Self::CommitWithInvalidProposals => {
                "A Commit message referencing one or more invalid proposals was received"
            }
            Self::CommitError(_) => "An error occured when applying a Commit message",
        }
    }
}
