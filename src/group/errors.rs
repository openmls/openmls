//! # MLS Group errors
//!
//! `WelcomeError`, `ApplyCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::config::ConfigError;
use crate::extensions::ExtensionError;
use crate::framing::errors::MLSCiphertextError;
use crate::tree::TreeError;

#[derive(PartialEq, Debug)]
#[repr(u16)]
pub enum GroupError {
    DecryptionError = 0,
}

#[derive(PartialEq, Debug)]
#[repr(u16)]
pub enum WelcomeError {
    CiphersuiteMismatch = 100,
    JoinerSecretNotFound = 101,
    MissingRatchetTree = 102,
    TreeHashMismatch = 103,
    JoinerNotInTree = 104,
    ConfirmationTagMismatch = 105,
    InvalidRatchetTree = 106,
    InvalidGroupInfoSignature = 107,
    GroupInfoDecryptionFailure = 108,
    DuplicateRatchetTreeExtension = 109,
    UnsupportedMlsVersion = 110,
    UnknownError = 111,
}

#[derive(PartialEq, Debug)]
#[repr(u16)]
pub enum ApplyCommitError {
    EpochMismatch = 200,
    WrongPlaintextContentType = 201,
    SelfRemoved = 202,
    PathKeyPackageVerificationFailure = 203,
    NoParentHashExtension = 204,
    ParentHashMismatch = 205,
    PlaintextSignatureFailure = 206,
    RequiredPathNotFound = 207,
    ConfirmationTagMismatch = 208,
    MissingOwnKeyPackage = 209,
    MissingProposal = 210,
    OwnKeyNotFound = 211,
}

#[derive(Debug)]
#[repr(u16)]
pub enum CreateCommitError {
    CannotRemoveSelf = 300,
    OwnKeyNotFound = 301,
}

impl From<MLSCiphertextError> for GroupError {
    fn from(_e: MLSCiphertextError) -> Self {
        GroupError::DecryptionError
    }
}

impl From<TreeError> for WelcomeError {
    fn from(e: TreeError) -> WelcomeError {
        match e {
            TreeError::DuplicateIndex => WelcomeError::InvalidRatchetTree,
            TreeError::InvalidArguments => WelcomeError::InvalidRatchetTree,
            TreeError::InvalidUpdatePath => WelcomeError::InvalidRatchetTree,
            TreeError::UnknownError => WelcomeError::UnknownError,
        }
    }
}

// TODO: Should get fixed in #83
impl From<ConfigError> for ApplyCommitError {
    // TODO: tbd in #83
    fn from(_e: ConfigError) -> ApplyCommitError {
        ApplyCommitError::NoParentHashExtension
    }
}

// TODO: Should get fixed in #83
impl From<ExtensionError> for ApplyCommitError {
    fn from(_e: ExtensionError) -> ApplyCommitError {
        ApplyCommitError::NoParentHashExtension
    }
}

// TODO: Should get fixed in #83
impl From<ConfigError> for WelcomeError {
    fn from(e: ConfigError) -> WelcomeError {
        match e {
            ConfigError::UnsupportedMlsVersion => WelcomeError::UnsupportedMlsVersion,
            ConfigError::UnsupportedCiphersuite => WelcomeError::CiphersuiteMismatch,
            _ => WelcomeError::UnknownError,
        }
    }
}
