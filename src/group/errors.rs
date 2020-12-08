//! # MLS Group errors
//!
//! `WelcomeError`, `ApplyCommitError`, `DecryptionError`, and
//! `CreateCommitError`.

use crate::config::ConfigError;
use crate::framing::errors::MLSCiphertextError;
use crate::tree::{secret_tree::SecretTypeError, TreeError};

implement_error! {
    pub enum GroupError {
        MLSCiphertextError(MLSCiphertextError) =
            "See [`MLSCiphertextError`](`crate::framing::errors::MLSCiphertextError`) for details",
        WelcomeError(WelcomeError) =
            "See [`WelcomeError`](`WelcomeError`) for details",
        ApplyCommitError(ApplyCommitError) =
            "See [`WelcomeError`](`ApplyCommitError`) for details",
        CreateCommitError(CreateCommitError) =
            "See [`WelcomeError`](`CreateCommitError`) for details",
        ConfigError(ConfigError) =
            "See [`ConfigError`](`crate::config::ConfigError`) for details",
        ExporterError(ExporterError) =
            "See [`ExporterError`](`ExporterError`) for details",
        SecretTypeError(SecretTypeError) =
            "See [`SecretTypeError`](`crate::tree::secret_tree::SecretTypeError`) for details",
    }
}

implement_error! {
    pub enum WelcomeError {
        CiphersuiteMismatch =
            "Ciphersuites in the Welcome message and the corresponding key package bundle don't match.",
        JoinerSecretNotFound =
            "No joiner secret found the Welcome message.",
        MissingRatchetTree =
            "No ratchet tree available to build initial tree after receiving a Welcome message",
        TreeHashMismatch =
            "The tree hash computed does not match the one in the GroupInfo.",
        ConfirmationTagMismatch =
             "The computed confirmation tag does not match the expected one.",
        InvalidRatchetTree =
            "Invalid ratchet tree in Welcome message.",
        InvalidGroupInfoSignature =
            "The signature on the GroupInfo is not valid.",
        GroupInfoDecryptionFailure =
            "Unable to decrypt the GroupInfo",
        DuplicateRatchetTreeExtension =
            "Found more than one ratchet tree extension in the Welcome message.",
        UnsupportedMlsVersion =
            "The Welcome message uses an unsupported MLS version",
        UnknownError =
            "An unknown error occurred.",
    }
}

implement_error! {
    pub enum ApplyCommitError {
        EpochMismatch =
            "Couldn't apply commit. The epoch of the group context and MLSPlaintext didn't match.",
        WrongPlaintextContentType =
            "apply_commit_internal was called with an MLSPlaintext that is not a Commit.",
        SelfRemoved =
            "Tried to apply a commit to a group we are not a part of.",
        PathKeyPackageVerificationFailure =
            "Unable to verify the key package signature.",
        NoParentHashExtension =
            "Parent hash extension is missing.",
        ParentHashMismatch =
            "Parent has values don't match.",
        PlaintextSignatureFailure =
            "MLSPlaintext signature is invalid.",
        RequiredPathNotFound =
            "Unable to determine commit path.",
        ConfirmationTagMismatch =
            "Confirmation tag is invalid.",
        MissingOwnKeyPackage =
            "No key package to apply own commit.",
        MissingProposal =
            "The proposal queue is missing a proposal for the commit.",
        OwnKeyNotFound =
            "Missing own key to apply proposal.",
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

impl From<TreeError> for WelcomeError {
    fn from(e: TreeError) -> WelcomeError {
        match e {
            TreeError::DuplicateIndex
            | TreeError::InvalidArguments
            | TreeError::InvalidUpdatePath => WelcomeError::InvalidRatchetTree,
            TreeError::UnknownError => WelcomeError::UnknownError,
        }
    }
}
