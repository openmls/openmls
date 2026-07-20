//! MLS Message (Output)
//!
//! This module defines the [`MlsMessageOut`] structs which implements the
//! `MLSMessage` struct as defined by the MLS specification, but is used
//! exclusively as output of the [`MlsGroup`] API. [`MlsMessageIn`] also
//! implements `MLSMessage`, but for inputs.
//!
//! The [`MlsMessageOut`] struct is meant to be serialized upon its return from
//! a function of the `MlsGroup` API so that it can be sent to the DS.

use super::*;

use crate::{key_packages::KeyPackage, messages::group_info::GroupInfo, versions::ProtocolVersion};

/// An [`MlsMessageOut`] is typically returned from an [`MlsGroup`] function and
/// meant to be serialized and sent to the DS.
#[derive(Debug, Clone, TlsSerialize, TlsSize)]
pub struct MlsMessageOut {
    pub(crate) version: ProtocolVersion,
    pub(crate) body: MlsMessageBodyOut,
}

/// MLSMessage (Body)
///
/// Note: Because [MlsMessageBodyOut] already discriminates between
/// `public_message`, `private_message`, etc., we don't use the
/// `wire_format` field. This prevents inconsistent assignments
/// where `wire_format` contradicts the variant given in `body`.
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
#[derive(Debug, Clone, TlsSerialize, TlsSize)]
#[repr(u16)]
pub enum MlsMessageBodyOut {
    /// Plaintext message
    #[tls_codec(discriminant = 1)]
    PublicMessage(PublicMessage),

    /// Ciphertext message
    #[tls_codec(discriminant = 2)]
    PrivateMessage(PrivateMessage),

    /// Welcome message
    #[tls_codec(discriminant = 3)]
    Welcome(Welcome),

    /// Group information
    #[tls_codec(discriminant = 4)]
    GroupInfo(GroupInfo),

    /// KeyPackage
    #[tls_codec(discriminant = 5)]
    #[allow(dead_code)]
    KeyPackage(KeyPackage),
}
