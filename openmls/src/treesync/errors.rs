//! TreeSync errors
//!
//! This module exposes [`ApplyUpdatePathError`] and [`PublicTreeError`].

use thiserror::Error;

use super::*;
use crate::{
    binary_tree::MlsBinaryTreeDiffError, ciphersuite::signable::SignatureError, error::LibraryError,
};

// === Public errors ===

/// Public tree error
#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum PublicTreeError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The derived public key doesn't match the one in the tree.
    #[error("The derived public key doesn't match the one in the tree.")]
    PublicKeyMismatch,
    /// Found two KeyPackages with the same public key.
    #[error("Found two KeyPackages with the same public key.")]
    DuplicateKeyPackage,
    /// Couldn't find our own key package in this tree.
    #[error("Couldn't find our own key package in this tree.")]
    MissingKeyPackage,
    /// The tree is malformed.
    #[error("The tree is malformed.")]
    MalformedTree,
    /// A parent hash was invalid.
    #[error("A parent hash was invalid.")]
    InvalidParentHash,
    /// An update failed because the provided credential has a different identity than the one in the leaf node.
    #[error("An update failed because the provided credential has a different identity than the one in the leaf node.")]
    IdentityMismatch,
    /// See [`SignatureError`] for more details.
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
}

/// Apply update path error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ApplyUpdatePathError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The length of the received update path and that of the sender's direct path do not match.
    #[error(
        "The length of the received update path and that of the sender's direct path do not match."
    )]
    PathLengthMismatch,
    /// The received update path and the derived nodes are not identical.
    #[error("The received update path and the derived nodes are not identical.")]
    PathMismatch,
    /// The parent hash of the ney key package is invalid.
    #[error("The parent hash of the ney key package is invalid.")]
    ParentHashMismatch,
    /// The parent hash of the ney key package is missing.
    #[error("The parent hash of the ney key package is missing.")]
    MissingParentHash,
    /// Unable to decrypt the path node.
    #[error("Unable to decrypt the path node.")]
    UnableToDecrypt,
    /// Unable to find sender in tree.
    #[error("Unable to find sender in tree.")]
    MissingSender,
    /// Tree is already at maximum size.
    #[error("Tree is already at maximum size.")]
    TreeFull,
    /// External Committer used the wrong index.
    #[error("External Committer used the wrong index.")]
    InconsistentSenderIndex,
}

// === Crate errors ===

// TODO: This will go away in #819 again.
// `UnsupportedExtension` is only used in tests for now
#[allow(dead_code)]
/// TreeSync error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum TreeSyncError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// A requested leaf is not in the tree.
    #[error("The leaf does not exist in the tree.")]
    LeafNotInTree,
    /// See [`TreeSyncSetPathError`] for more details.
    #[error(transparent)]
    SetPathError(#[from] DerivePathError),
    /// See [`MlsBinaryTreeError`] for more details.
    #[error(transparent)]
    BinaryTreeError(#[from] MlsBinaryTreeError),
    /// See [`TreeSyncDiffError`] for more details.
    #[error(transparent)]
    TreeSyncDiffError(#[from] TreeSyncDiffError),
    /// See [`PathSecretError`] for more details.
    #[error(transparent)]
    DerivationError(#[from] PathSecretError),

    /// See [`CryptoError`] for more details.
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    /// An extension type is not supported by a leaf in the tree.
    #[error("An extension type is not supported by a leaf in the tree.")]
    UnsupportedExtension,
    /// A capability is not supported by a leaf in the tree.
    #[error("A capability is not supported by a leaf in the tree.")]
    UnsupportedCapabilities,
    /// A proposal is not supported by a leaf in the tree.
    #[error("A proposal is not supported by a leaf in the tree.")]
    UnsupportedProposal,
}

/// Derive path error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum DerivePathError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The derived public key doesn't match the one in the tree.
    #[error("The derived public key doesn't match the one in the tree.")]
    PublicKeyMismatch,
}

/// TreeSync set path error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TreeSyncAddLeaf {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// The tree is full, we cannot add any more leaves.
    #[error("The tree is full, we cannot add any more leaves.")]
    TreeFull,
}

/// TreeSync from nodes error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TreeSyncFromNodesError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`PublicTreeError`] for more details.
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
    /// See [`RatchetTreeError`] for more details.
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
}

/// TreeSync parent hash error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum TreeSyncParentHashError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Parent hash mismatch.
    #[error("Parent hash mismatch.")]
    InvalidParentHash,
}

/// TreeSync parent hash error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum TreeSyncDiffError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(
        "Couldn't find a fitting private key in the filtered resolution of the given leaf index."
    )]
    NoPrivateKeyFound,
    /// See [`MlsBinaryTreeDiffError`] for more details.
    #[error(transparent)]
    TreeDiffError(#[from] MlsBinaryTreeDiffError),
    /// See [`PathSecretError`] for more details.
    #[error(transparent)]
    DerivationError(#[from] PathSecretError),
    /// See [`MlsBinaryTreeError`] for more details.
    #[error(transparent)]
    CreationError(#[from] MlsBinaryTreeError),
}

/// TreeKem error
#[derive(Error, Debug, PartialEq, Clone)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum TreeKemError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// See [`TreeSyncError`] for more details.
    #[error(transparent)]
    TreeSyncError(#[from] TreeSyncError),
    /// See [`TreeSyncDiffError`] for more details.
    #[error(transparent)]
    TreeSyncDiffError(#[from] TreeSyncDiffError),
    /// See [`PathSecretError`] for more details.
    #[error(transparent)]
    PathSecretError(#[from] PathSecretError),
}

/// Errors that can happen during leaf node validation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LeafNodeValidationError {
    /// Lifetime is not acceptable.
    #[error("Lifetime is not acceptable.")]
    Lifetime(LifetimeError),
    /// Extensions are not acceptable.
    #[error("Extensions are not acceptable.")]
    UnsupportedExtensions,
    /// Proposals are not acceptable.
    #[error("Proposals are not acceptable.")]
    UnsupportedProposals,
    /// Credentials are not acceptable.
    #[error("Credentials are not acceptable.")]
    UnsupportedCredentials,
    /// The leaf node's credential type is not listed in the leaf node's capabilities."
    #[error("The leaf node's credential type is not listed in the leaf node's capabilities.")]
    CredentialNotInCapabilities,
    /// The leaf node's extension types are not (all) listed in the leaf node's capabilities.
    #[error(
        "The leaf node's extension types are not (all) listed in the leaf node's capabilities."
    )]
    ExtensionsNotInCapabilities,
    /// The group's ciphersuite is not listed in the leaf node's capabilities.
    #[error("The group's ciphersuite is not listed in the leaf node's capabilities.")]
    CiphersuiteNotInCapabilities,
    /// The leaf node's signature key is already used in the group.
    #[error("The leaf node's signature key is already used in the group.")]
    SignatureKeyAlreadyInUse,
    /// The leaf node's encryption key is already used in the group.
    #[error("The leaf node's encryption key is already used in the group.")]
    EncryptionKeyAlreadyInUse,
    /// The leaf node source is invalid in the given context.
    #[error("The leaf node source is invalid in the given context.")]
    InvalidLeafNodeSource,
    /// The leaf node credential is not supported by all members in the group.
    #[error("The leaf node credential is not supported by all members in the group.")]
    LeafNodeCredentialNotSupportedByMember,
    /// The credential used by a member is not supported by this leaf node.
    #[error("The credential used by a member is not supported by this leaf node.")]
    MemberCredentialNotSupportedByLeafNode,
}

/// Errors that can happen during lifetime validation.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LifetimeError {
    /// Lifetime range is too wide.
    #[error("Lifetime range is too wide.")]
    RangeTooBig,
    /// Lifetime doesn't cover current time.
    #[error("Lifetime doesn't cover current time.")]
    NotCurrent,
}

/// Errors that can happen during path validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum UpdatePathError {
    /// The update path contains an invalid type of leaf node.
    #[error("The update path contains an invalid type of leaf node.")]
    InvalidType,
    /// See [`SignatureError`] for more details.
    #[error(transparent)]
    SignatureError(#[from] SignatureError),
}
