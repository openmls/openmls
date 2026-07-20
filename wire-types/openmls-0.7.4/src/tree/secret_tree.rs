use openmls_traits::types::CryptoError;
use thiserror::Error;
use tls_codec::{Error as TlsCodecError, TlsSerialize, TlsSize};

use super::*;
use crate::{
    binary_tree::{array_representation::TreeSize, LeafNodeIndex},
    tree::sender_ratchet::*,
};

/// Secret tree error
#[derive(Error, Debug, Eq, PartialEq, Clone)]
pub enum SecretTreeError {
    /// Generation is too old to be processed.
    #[error("Generation is too old to be processed.")]
    TooDistantInThePast,
    /// Generation is too far in the future to be processed.
    #[error("Generation is too far in the future to be processed.")]
    TooDistantInTheFuture,
    /// Index out of bounds
    #[error("Index out of bounds")]
    IndexOutOfBounds,
    /// The requested secret was deleted to preserve forward secrecy.
    #[error("The requested secret was deleted to preserve forward secrecy.")]
    SecretReuseError,
    /// Cannot create decryption secrets from own sender ratchet or encryption secrets from the sender ratchets of other members.
    #[error("Cannot create decryption secrets from own sender ratchet or encryption secrets from the sender ratchets of other members.")]
    RatchetTypeError,
    /// Ratchet generation has reached `u32::MAX`.
    #[error("Ratchet generation has reached `u32::MAX`.")]
    RatchetTooLong,
    /// An unrecoverable error has occurred due to a bug in the implementation.
    #[error("An unrecoverable error has occurred due to a bug in the implementation.")]
    LibraryError,
    /// See [`TlsCodecError`] for more details.
    #[error(transparent)]
    CodecError(#[from] TlsCodecError),
    /// See [`CryptoError`] for more details.
    #[error(transparent)]
    CryptoError(#[from] CryptoError),
}

#[derive(Debug, TlsSerialize, TlsSize)]
pub(crate) struct TreeContext {
    pub(crate) node: u32,
    pub(crate) generation: u32,
}

#[derive(Debug, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub(crate) struct SecretTreeNode {
    pub(crate) secret: Secret,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SecretTree {
    own_index: LeafNodeIndex,
    leaf_nodes: Vec<Option<SecretTreeNode>>,
    parent_nodes: Vec<Option<SecretTreeNode>>,
    handshake_sender_ratchets: Vec<Option<SenderRatchet>>,
    application_sender_ratchets: Vec<Option<SenderRatchet>>,
    size: TreeSize,
}
