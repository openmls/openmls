//! MLS Message (Output)
//!
//! This module defines the [`MlsMessageOut`] structs which implements the
//! `MLSMessage` struct as defined by the MLS specification, but is used
//! exclusively as output of the [`MlsGroup`] API. [`MlsMessageIn`] also
//! implements `MLSMessage`, but for inputs.
//!
//! The [`MlsMessageOut`] struct is meant to be serialized upon its return from
//! a function of the `MlsGroup` API so that it can be sent to the DS.
use tls_codec::Serialize;

use super::*;

use crate::{
    key_packages::KeyPackage, messages::group_info::GroupInfo, prelude::KeyPackageBundle,
    versions::ProtocolVersion,
};

#[cfg(any(feature = "test-utils", test))]
use crate::messages::group_info::VerifiableGroupInfo;

/// An [`MlsMessageOut`] is typically returned from an [`MlsGroup`] function and
/// meant to be serialized and sent to the DS.
#[derive(Debug, Clone, PartialEq, TlsSerialize, TlsSize)]
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
#[derive(Debug, PartialEq, Clone, TlsSerialize, TlsSize)]
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

impl From<PublicMessage> for MlsMessageOut {
    fn from(public_message: PublicMessage) -> Self {
        Self {
            // TODO #34: The version should be set explicitly here instead of
            // the default.
            version: ProtocolVersion::default(),
            body: MlsMessageBodyOut::PublicMessage(public_message),
        }
    }
}

impl From<PrivateMessage> for MlsMessageOut {
    fn from(private_message: PrivateMessage) -> Self {
        Self {
            // TODO #34: The version should be set explicitly here instead of
            // the default.
            version: ProtocolVersion::default(),
            body: MlsMessageBodyOut::PrivateMessage(private_message),
        }
    }
}

impl From<GroupInfo> for MlsMessageOut {
    fn from(group_info: GroupInfo) -> Self {
        Self {
            version: group_info.group_context().protocol_version(),
            body: MlsMessageBodyOut::GroupInfo(group_info),
        }
    }
}

impl From<KeyPackage> for MlsMessageOut {
    fn from(key_package: KeyPackage) -> Self {
        Self {
            version: key_package.protocol_version(),
            body: MlsMessageBodyOut::KeyPackage(key_package),
        }
    }
}

impl From<KeyPackageBundle> for MlsMessageOut {
    fn from(key_package: KeyPackageBundle) -> Self {
        Self {
            version: key_package.key_package().protocol_version(),
            body: MlsMessageBodyOut::KeyPackage(key_package.key_package),
        }
    }
}

impl MlsMessageOut {
    /// Create an [`MlsMessageOut`] from a [`PrivateMessage`], as well as the
    /// currently used [`ProtocolVersion`].
    pub(crate) fn from_private_message(
        private_message: PrivateMessage,
        version: ProtocolVersion,
    ) -> Self {
        Self {
            version,
            body: MlsMessageBodyOut::PrivateMessage(private_message),
        }
    }

    /// Create an [`MlsMessageOut`] from a [`Welcome`] message and the currently
    /// used [`ProtocolVersion`].
    pub fn from_welcome(welcome: Welcome, version: ProtocolVersion) -> Self {
        MlsMessageOut {
            version,
            body: MlsMessageBodyOut::Welcome(welcome),
        }
    }

    /// Serializes the message to a byte vector. Returns [`MlsMessageError::UnableToEncode`] on failure.
    pub fn to_bytes(&self) -> Result<Vec<u8>, MlsMessageError> {
        self.tls_serialize_detached()
            .map_err(|_| MlsMessageError::UnableToEncode)
    }

    /// Returns a reference to the contents of this [`MlsMessageOut`].
    pub fn body(&self) -> &MlsMessageBodyOut {
        &self.body
    }
}

// Convenience functions for tests and test-utils

#[cfg(any(feature = "test-utils", test))]
impl MlsMessageOut {
    /// Turn an [`MlsMessageOut`] into a [`Welcome`].
    #[cfg(any(feature = "test-utils", test))]
    pub fn into_welcome(self) -> Option<Welcome> {
        match self.body {
            MlsMessageBodyOut::Welcome(w) => Some(w),
            _ => None,
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn into_protocol_message(self) -> Option<ProtocolMessage> {
        let mls_message_in: MlsMessageIn = self.into();

        match mls_message_in.extract() {
            MlsMessageBodyIn::PublicMessage(pm) => Some(pm.into()),
            MlsMessageBodyIn::PrivateMessage(pm) => Some(pm.into()),
            _ => None,
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn into_verifiable_group_info(self) -> Option<VerifiableGroupInfo> {
        match self.body {
            MlsMessageBodyOut::GroupInfo(group_info) => {
                Some(group_info.into_verifiable_group_info())
            }
            _ => None,
        }
    }
}

// The following two `From` implementations break abstraction layers and MUST
// NOT be made available outside of tests or "test-utils".

#[cfg(any(feature = "test-utils", test))]
impl From<MlsMessageIn> for MlsMessageOut {
    fn from(mls_message: MlsMessageIn) -> Self {
        let version = mls_message.version;
        let body = match mls_message.body {
            MlsMessageBodyIn::Welcome(w) => MlsMessageBodyOut::Welcome(w),
            MlsMessageBodyIn::GroupInfo(gi) => MlsMessageBodyOut::GroupInfo(gi.into()),
            MlsMessageBodyIn::KeyPackage(kp) => MlsMessageBodyOut::KeyPackage(kp.into()),
            MlsMessageBodyIn::PublicMessage(pm) => MlsMessageBodyOut::PublicMessage(pm.into()),
            MlsMessageBodyIn::PrivateMessage(pm) => MlsMessageBodyOut::PrivateMessage(pm.into()),
        };
        Self { version, body }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<MlsMessageOut> for MlsMessageIn {
    fn from(mls_message_out: MlsMessageOut) -> Self {
        let version = mls_message_out.version;
        let body = match mls_message_out.body {
            MlsMessageBodyOut::PublicMessage(pm) => MlsMessageBodyIn::PublicMessage(pm.into()),
            MlsMessageBodyOut::PrivateMessage(pm) => MlsMessageBodyIn::PrivateMessage(pm.into()),
            MlsMessageBodyOut::Welcome(w) => MlsMessageBodyIn::Welcome(w),
            MlsMessageBodyOut::GroupInfo(gi) => {
                MlsMessageBodyIn::GroupInfo(gi.into_verifiable_group_info())
            }
            MlsMessageBodyOut::KeyPackage(kp) => MlsMessageBodyIn::KeyPackage(kp.into()),
        };
        Self { version, body }
    }
}
