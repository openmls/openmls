//! MLS Message (Input)
//!
//! This module defines the [`MlsMessageIn`] structs which implements the
//! `MLSMessage` struct as defined by the MLS specification, but is used
//! exclusively as input for the [`MlsGroup`] API. [`MlsMessageOut`] also
//! implements `MLSMessage`, but for outputs.
//!
//! The [`MlsMessageIn`] struct is meant to be deserialized upon receiving it
//! from the DS. After deserialization, its content (either a [`PublicMessage`],
//! [`PrivateMessage`], [`KeyPackageIn`], [`Welcome`] or
//! [`GroupInfo`](crate::messages::group_info::GroupInfo)) can be extracted via
//! [`MlsMessageIn::extract()`] for use with the [`MlsGroup`] API.
//!
//! If an [`MlsMessageIn`] contains a [`PublicMessage`] or [`PrivateMessage`],
//! can be used to determine which group can be used to process the message.

use super::*;
use crate::{
    key_packages::KeyPackageIn, messages::group_info::VerifiableGroupInfo,
    versions::ProtocolVersion,
};

/// Before use with the [`MlsGroup`] API, the message has to be unpacked via
/// `extract` to yield its [`MlsMessageBodyIn`].
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     ProtocolVersion version = mls10;
///
///     // ... continued in [MlsMessageBody] ...
/// } MLSMessage;
/// ```
///
/// The `-In` suffix of this struct is to separate it from the [`MlsMessageOut`]
/// which is commonly returned by functions of the [`MlsGroup`] API.
#[derive(Debug, Clone, TlsSize)]
pub struct MlsMessageIn {
    pub(crate) version: ProtocolVersion,
    pub(crate) body: MlsMessageBodyIn,
}

/// MLSMessage (Body)
///
/// Note: Because [`MlsMessageBodyIn`] already discriminates between
/// `public_message`, `private_message`, etc., we don't use the `wire_format`
/// field. This prevents inconsistent assignments where `wire_format`
/// contradicts the variant given in `body`.
///
/// ```c
/// // draft-ietf-mls-protocol-17
/// struct {
///     // ... continued from [MlsMessage] ...
///
///     WireFormat wire_format;
///     select (MLSMessage.wire_format) {
///         case mls_plaintext:
///             PublicMessage plaintext;
///         case mls_ciphertext:
///             PrivateMessage ciphertext;
///         case mls_welcome:
///             Welcome welcome;
///         case mls_group_info:
///             GroupInfo group_info;
///         case mls_key_package:
///             KeyPackage key_package;
///     }
/// } MLSMessage;
/// ```
#[derive(Debug, Clone, TlsDeserialize, TlsDeserializeBytes, TlsSize)]
#[repr(u16)]
pub enum MlsMessageBodyIn {
    /// Plaintext message
    #[tls_codec(discriminant = 1)]
    PublicMessage(PublicMessageIn),

    /// Ciphertext message
    #[tls_codec(discriminant = 2)]
    PrivateMessage(PrivateMessageIn),

    /// Welcome message
    #[tls_codec(discriminant = 3)]
    Welcome(Welcome),

    /// Group information
    #[tls_codec(discriminant = 4)]
    GroupInfo(VerifiableGroupInfo),

    /// KeyPackage
    #[tls_codec(discriminant = 5)]
    KeyPackage(KeyPackageIn),
}
