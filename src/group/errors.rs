use crate::errors::ConfigError;
use crate::extensions::ExtensionError;
use crate::framing::*;
use crate::tree::TreeError;

#[derive(Debug)]
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
}

#[derive(PartialEq, Debug)]
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
pub enum DecryptionError {
    CiphertextError(MLSCiphertextError),
}

impl From<MLSCiphertextError> for DecryptionError {
    fn from(e: MLSCiphertextError) -> DecryptionError {
        DecryptionError::CiphertextError(e)
    }
}

#[derive(Debug)]
pub enum CreateCommitError {
    CannotRemoveSelf = 300,
    OwnKeyNotFound = 301,
}

impl From<TreeError> for WelcomeError {
    fn from(e: TreeError) -> WelcomeError {
        match e {
            TreeError::DuplicateIndex => WelcomeError::InvalidRatchetTree,
            TreeError::InvalidArguments => WelcomeError::InvalidRatchetTree,
            TreeError::InvalidUpdatePath => WelcomeError::InvalidRatchetTree,
            TreeError::NoneError => WelcomeError::InvalidRatchetTree,
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
