//! # Extensions
//!
//! In MLS, extensions appear in the following places:
//!
//! - In [`KeyPackages`](`crate::key_packages`), to describe client capabilities
//!   and aspects of their participation in the group.
//!
//! - In `GroupInfo`, to inform new members of the group's parameters and to
//!   provide any additional information required to join the group.
//!
//! - In the `GroupContext` object, to ensure that all members of the group have
//!   a consistent view of the parameters in use.
//!
//! Note that `GroupInfo` and `GroupContext` are not exposed via OpenMLS' public
//! API.
//!
//! OpenMLS supports the following extensions:
//!
//! - [`ApplicationIdExtension`] (KeyPackage extension)
//! - [`RatchetTreeExtension`] (GroupInfo extension)
//! - [`RequiredCapabilitiesExtension`] (GroupContext extension)
//! - [`ExternalPubExtension`] (GroupInfo extension)

use std::{
    fmt::Debug,
    io::{Read, Write},
};

use serde::{Deserialize, Serialize};

// Private
mod application_id_extension;
mod codec;
mod external_pub_extension;
mod external_sender_extension;
mod last_resort;
mod ratchet_tree_extension;
mod required_capabilities;
use errors::*;

// Public
pub mod errors;

// Public re-exports
pub use application_id_extension::ApplicationIdExtension;
pub use external_pub_extension::ExternalPubExtension;
pub use external_sender_extension::{
    ExternalSender, ExternalSendersExtension, SenderExtensionIndex,
};
pub use last_resort::LastResortExtension;
pub use ratchet_tree_extension::RatchetTreeExtension;
pub use required_capabilities::RequiredCapabilitiesExtension;
use tls_codec::{
    Deserialize as TlsDeserializeTrait, DeserializeBytes, Error, Serialize as TlsSerializeTrait,
    Size, TlsSize,
};

/// MLS Extension Types
///
/// Copied from draft-ietf-mls-protocol-16:
///
/// | Value            | Name                     | Message(s) | Recommended | Reference |
/// |:-----------------|:-------------------------|:-----------|:------------|:----------|
/// | 0x0000           | RESERVED                 | N/A        | N/A         | RFC XXXX  |
/// | 0x0001           | application_id           | LN         | Y           | RFC XXXX  |
/// | 0x0002           | ratchet_tree             | GI         | Y           | RFC XXXX  |
/// | 0x0003           | required_capabilities    | GC         | Y           | RFC XXXX  |
/// | 0x0004           | external_pub             | GI         | Y           | RFC XXXX  |
/// | 0x0005           | external_senders         | GC         | Y           | RFC XXXX  |
/// | 0xff00  - 0xffff | Reserved for Private Use | N/A        | N/A         | RFC XXXX  |
///
/// Note: OpenMLS does not provide a `Reserved` variant in [ExtensionType].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub enum ExtensionType {
    /// The application id extension allows applications to add an explicit,
    /// application-defined identifier to a KeyPackage.
    ApplicationId,

    /// The ratchet tree extensions provides the whole public state of the
    /// ratchet tree.
    RatchetTree,

    /// The required capabilities extension defines the configuration of a group
    /// that imposes certain requirements on clients in the group.
    RequiredCapabilities,

    /// To join a group via an External Commit, a new member needs a GroupInfo
    /// with an ExternalPub extension present in its extensions field.
    ExternalPub,

    /// Group context extension that contains the credentials and signature keys
    /// of senders that are permitted to send external proposals to the group.
    ExternalSenders,

    /// KeyPackage extension that marks a KeyPackage for use in a last resort
    /// scenario.
    LastResort,

    /// A currently unknown extension type.
    Unknown(u16),
}

impl Size for ExtensionType {
    fn tls_serialized_len(&self) -> usize {
        2
    }
}

impl TlsDeserializeTrait for ExtensionType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut extension_type = [0u8; 2];
        bytes.read_exact(&mut extension_type)?;

        Ok(ExtensionType::from(u16::from_be_bytes(extension_type)))
    }
}

impl DeserializeBytes for ExtensionType {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let extension_type = ExtensionType::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[extension_type.tls_serialized_len()..];
        Ok((extension_type, remainder))
    }
}

impl TlsSerializeTrait for ExtensionType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&u16::from(*self).to_be_bytes())?;

        Ok(2)
    }
}

impl From<u16> for ExtensionType {
    fn from(a: u16) -> Self {
        match a {
            1 => ExtensionType::ApplicationId,
            2 => ExtensionType::RatchetTree,
            3 => ExtensionType::RequiredCapabilities,
            4 => ExtensionType::ExternalPub,
            5 => ExtensionType::ExternalSenders,
            10 => ExtensionType::LastResort,
            unknown => ExtensionType::Unknown(unknown),
        }
    }
}

impl From<ExtensionType> for u16 {
    fn from(value: ExtensionType) -> Self {
        match value {
            ExtensionType::ApplicationId => 1,
            ExtensionType::RatchetTree => 2,
            ExtensionType::RequiredCapabilities => 3,
            ExtensionType::ExternalPub => 4,
            ExtensionType::ExternalSenders => 5,
            ExtensionType::LastResort => 10,
            ExtensionType::Unknown(unknown) => unknown,
        }
    }
}

/// # Extension
///
/// An extension is one of the [`Extension`] enum values.
/// The enum provides a set of common functionality for all extensions.
///
/// See the individual extensions for more details on each extension.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<V>;
/// } Extension;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Extension {
    /// An [`ApplicationIdExtension`]
    ApplicationId(ApplicationIdExtension),

    /// A [`RatchetTreeExtension`]
    RatchetTree(RatchetTreeExtension),

    /// A [`RequiredCapabilitiesExtension`]
    RequiredCapabilities(RequiredCapabilitiesExtension),

    /// An [`ExternalPubExtension`]
    ExternalPub(ExternalPubExtension),

    /// An [`ExternalSendersExtension`]
    ExternalSenders(ExternalSendersExtension),

    /// A [`LastResortExtension`]
    LastResort(LastResortExtension),

    /// A currently unknown extension.
    Unknown(u16, UnknownExtension),
}

/// A unknown/unparsed extension represented by raw bytes.
#[derive(PartialEq, Eq, Clone, Debug, Serialize, Deserialize)]
pub struct UnknownExtension(pub Vec<u8>);

/// A list of extensions with unique extension types.
#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSize)]
pub struct Extensions {
    unique: Vec<Extension>,
}

impl TlsSerializeTrait for Extensions {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.unique.tls_serialize(writer)
    }
}

impl TlsDeserializeTrait for Extensions {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let candidate: Vec<Extension> = Vec::tls_deserialize(bytes)?;
        Extensions::try_from(candidate)
            .map_err(|_| Error::DecodingError("Found duplicate extensions".into()))
    }
}

impl DeserializeBytes for Extensions {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let extensions = Extensions::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[extensions.tls_serialized_len()..];
        Ok((extensions, remainder))
    }
}

impl TryFrom<Vec<Extension>> for Extensions {
    type Error = InvalidExtensionError;

    fn try_from(candidate: Vec<Extension>) -> Result<Self, Self::Error> {
        let mut unique: Vec<Extension> = Vec::new();

        for extension in candidate.into_iter() {
            if unique
                .iter()
                .any(|ext| ext.extension_type() == extension.extension_type())
            {
                return Err(InvalidExtensionError::Duplicate);
            } else {
                unique.push(extension);
            }
        }

        Ok(Self { unique })
    }
}

impl Extension {
    /// Returns the [`ExtensionType`]
    #[inline]
    pub const fn extension_type(&self) -> ExtensionType {
        match self {
            Extension::ApplicationId(_) => ExtensionType::ApplicationId,
            Extension::RatchetTree(_) => ExtensionType::RatchetTree,
            Extension::RequiredCapabilities(_) => ExtensionType::RequiredCapabilities,
            Extension::ExternalPub(_) => ExtensionType::ExternalPub,
            Extension::ExternalSenders(_) => ExtensionType::ExternalSenders,
            Extension::LastResort(_) => ExtensionType::LastResort,
            Extension::Unknown(kind, _) => ExtensionType::Unknown(*kind),
        }
    }
}
