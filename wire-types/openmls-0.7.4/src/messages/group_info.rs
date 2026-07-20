//! This module contains all types related to group info handling.

use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use thiserror::Error;
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    binary_tree::LeafNodeIndex, ciphersuite::Signature, extensions::Extensions,
    group::GroupContext, messages::ConfirmationTag,
};

/// A type that represents a group info of which the signature has not been verified.
/// It implements the [`Verifiable`] trait and can be turned into a group info by calling
/// `verify(...)` with the signature key of the [`Credential`](crate::credentials::Credential).
/// When receiving a serialized group info, it can only be deserialized into a
/// [`VerifiableGroupInfo`], which can then be turned into a group info as described above.
#[derive(Debug, Clone, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
pub struct VerifiableGroupInfo {
    payload: GroupInfoTBS,
    signature: Signature,
}

/// Error related to group info.
#[derive(Error, Debug, PartialEq, Clone)]
pub enum GroupInfoError {
    /// Decryption failed.
    #[error("Decryption failed.")]
    DecryptionFailed,
    /// Malformed.
    #[error("Malformed.")]
    Malformed,
}

/// GroupInfo
///
/// Note: The struct is split into a `GroupInfoTBS` payload and a signature.
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     GroupContext group_context;
///     Extension extensions<V>;
///     MAC confirmation_tag;
///     uint32 signer;
///     /* SignWithLabel(., "GroupInfoTBS", GroupInfoTBS) */
///     opaque signature<V>;
/// } GroupInfo;
/// ```
#[derive(Debug, Clone, TlsSerialize, TlsSize, SerdeSerialize, SerdeDeserialize)]
pub struct GroupInfo {
    payload: GroupInfoTBS,
    signature: Signature,
}

/// GroupInfo (To Be Signed)
///
/// ```c
/// // draft-ietf-mls-protocol-16
///
/// struct {
///     GroupContext group_context;
///     Extension extensions<V>;
///     MAC confirmation_tag;
///     uint32 signer;
/// } GroupInfoTBS;
/// ```
#[derive(
    Debug,
    Clone,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
    SerdeSerialize,
    SerdeDeserialize,
)]
pub(crate) struct GroupInfoTBS {
    group_context: GroupContext,
    extensions: Extensions,
    confirmation_tag: ConfirmationTag,
    signer: LeafNodeIndex,
}

// -------------------------------------------------------------------------------------------------
