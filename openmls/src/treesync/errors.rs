use thiserror::Error;

use super::*;
use crate::{binary_tree::MlsBinaryTreeDiffError, error::LibraryError};
use tls_codec::Error as TlsCodecError;

// === Public errors ===

/// Public tree error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum PublicTreeError {
    #[error("The derived public key doesn't match the one in the tree.")]
    PublicKeyMismatch,
    #[error("Found two KeyPackages with the same public key.")]
    DuplicateKeyPackage,
    #[error("Couldn't find our own key package in this tree.")]
    MissingKeyPackage,
    #[error("The tree is malformed.")]
    MalformedTree,
    #[error("A parent hash was invalid.")]
    InvalidParentHash,
}

/// Apply update path error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum ApplyUpdatePathError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The received update path and the derived nodes are not identical.")]
    PathMismatch,
    #[error("The parent hash of the ney key package is invalid.")]
    ParentHashMismatch,
    #[error("The parent hash of the ney key package is missing.")]
    MissingParentHash,
    #[error("Unable to decrypt the path node.")]
    UnableToDecrypt,
}

// === Crate errors ===

/// TreeSync error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TreeSyncError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Found two KeyPackages with the same public key.")]
    KeyPackageRefNotInTree,
    #[error(transparent)]
    SetPathError(#[from] TreeSyncSetPathError),
    #[error(transparent)]
    BinaryTreeError(#[from] MlsBinaryTreeError),
    #[error(transparent)]
    TreeSyncNodeError(#[from] TreeSyncNodeError),
    #[error(transparent)]
    NodeTypeError(#[from] NodeError),
    #[error(transparent)]
    TreeSyncDiffError(#[from] TreeSyncDiffError),
    #[error(transparent)]
    DerivationError(#[from] PathSecretError),
    #[error(transparent)]
    SenderError(#[from] SenderError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

/// TreeSync set path error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TreeSyncSetPathError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The derived public key doesn't match the one in the tree.")]
    PublicKeyMismatch,
}

/// TreeSync set path error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TreeSyncAddLeaf {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The tree is full, we cannot add any more leaves.")]
    TreeFull,
}

/// TreeSync from nodes error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum TreeSyncFromNodesError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error(transparent)]
    PublicTreeError(#[from] PublicTreeError),
}

/// TreeSync parent hash error
#[derive(Error, Debug, PartialEq, Clone)]
pub(crate) enum TreeSyncParentHashError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("Parent hash mismatch.")]
    InvalidParentHash,
}

/// TreeSync parent hash error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TreeSyncDiffError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The given path does not have the length of the given leaf's direct path.")]
    PathLengthError,
    #[error("The given key package does not contain a parent hash extension.")]
    MissingParentHash,
    #[error("The parent hash of the given key package is invalid.")]
    ParentHashMismatch,
    #[error("The parent hash of a node in the given tree is invalid.")]
    InvalidParentHash,
    #[error("The leaf index in the unmerged leaves of a parent node point to a blank.")]
    BlankUnmergedLeaf,
    #[error(
        "Couldn't find a fitting private key in the filtered resolution of the given leaf index."
    )]
    NoPrivateKeyFound,
    #[error(transparent)]
    NodeTypeError(#[from] NodeError),
    #[error(transparent)]
    TreeSyncNodeError(#[from] TreeSyncNodeError),
    #[error(transparent)]
    TreeDiffError(#[from] MlsBinaryTreeDiffError),
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
    #[error(transparent)]
    DerivationError(#[from] PathSecretError),
    #[error(transparent)]
    CreationError(#[from] MlsBinaryTreeError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
}

/// TreeKem error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TreeKemError {
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    #[error("The given path to encrypt does not have the same length as the direct path.")]
    PathLengthError,
    #[error("Couldn't find the path secret to encrypt for one of the new members.")]
    PathSecretNotFound,
    #[error(transparent)]
    TreeSyncError(#[from] TreeSyncError),
    #[error(transparent)]
    TreeSyncDiffError(#[from] TreeSyncDiffError),
    #[error(transparent)]
    PathSecretError(#[from] PathSecretError),
    #[error(transparent)]
    EncodingError(#[from] TlsCodecError),
    #[error(transparent)]
    KeyPackageError(#[from] KeyPackageError),
}
