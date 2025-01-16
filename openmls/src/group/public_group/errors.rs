use thiserror::Error;

use crate::{
    error::LibraryError,
    extensions::errors::InvalidExtensionError,
    treesync::errors::{LeafNodeValidationError, TreeSyncFromNodesError},
};

/// Public group creation from external error.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum CreationFromExternalError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// This error indicates the public tree is invalid. See [`TreeSyncFromNodesError`] for more details.
    #[error(transparent)]
    TreeSyncError(#[from] TreeSyncFromNodesError),
    /// Sender not found in tree.
    #[error("Sender not found in tree.")]
    UnknownSender,
    /// The signature on the GroupInfo is not valid.
    #[error("The signature on the GroupInfo is not valid.")]
    InvalidGroupInfoSignature,
    /// The computed tree hash does not match the one in the GroupInfo.
    #[error("The computed tree hash does not match the one in the GroupInfo.")]
    TreeHashMismatch,
    /// We don't support the version of the group we are trying to join.
    #[error("We don't support the version of the group we are trying to join.")]
    UnsupportedMlsVersion,
    /// See [`LeafNodeValidationError`]
    #[error(transparent)]
    LeafNodeValidation(#[from] LeafNodeValidationError),
    /// Error writing to storage.
    #[error("Error writing to storage: {0}")]
    WriteToStorageError(StorageError),
    /// A parent node has an unmerged leaf that is not a descendant of the node.
    #[error("A parent node has an unmerged leaf that is not a descendant of the node")]
    UnmergedLeafNotADescendant,
    /// Found a path from a parent with an unmerged leaf to the leaf with nodes that do not have that as a leaf  
    #[error("Found a path from a parent with an unmerged leaf to the leaf with nodes that do not have that as a leaf")]
    IntermediateNodeMissingUnmergedLeaf,
    /// The ratchet tree contains duplcate encryption keys
    #[error("The ratchet tree contains duplcate encryption keys")]
    DuplicateEncryptionKey,
}

/// Public group builder error.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum PublicGroupBuildError {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// Invalid extensions set in configuration
    #[error("Invalid extensions set in configuration")]
    InvalidExtensions(#[from] InvalidExtensionError),
}
