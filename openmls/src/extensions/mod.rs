//! # Extensions
//!
//! ## Extension struct
//!
//! An extension has an `ExtensionType` and an opaque payload (byte vector).
//! This isn't used in OpenMLS at all but part of the (de)serialization process
//! of each extension.
//!
//! See IANA registry for registered values
//!
//! ```text
//! uint16 ExtensionType;
//!
//! struct {
//!     ExtensionType extension_type;
//!     opaque extension_data<0..2^32-1>;
//! } Extension;
//! ```

use std::{
    convert::TryFrom,
    fmt::Debug,
    io::{Read, Write},
};

pub(crate) use serde::{Deserialize, Serialize};

mod capabilities_extension;
pub mod errors;
mod key_package_id_extension;
mod life_time_extension;
mod parent_hash_extension;
mod ratchet_tree_extension;
mod required_capabilities;
use tls_codec::{Size, TlsByteVecU32, TlsDeserialize, TlsSerialize, TlsSize, TlsSliceU32};

pub use capabilities_extension::CapabilitiesExtension;
pub use errors::*;
pub use key_package_id_extension::KeyIdExtension;
pub use life_time_extension::LifetimeExtension;
pub(crate) use parent_hash_extension::ParentHashExtension;
pub use ratchet_tree_extension::RatchetTreeExtension;
pub use required_capabilities::RequiredCapabilitiesExtension;

#[cfg(test)]
mod test_extensions;

/// # Extension types
///
/// [IANA registrations](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-mls-extension-types)
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Ord,
    PartialOrd,
    TlsSerialize,
    TlsDeserialize,
    TlsSize,
)]
#[repr(u16)]
pub enum ExtensionType {
    Reserved = 0,
    Capabilities = 1,
    Lifetime = 2,
    KeyId = 3,
    ParentHash = 4,
    RatchetTree = 5,
    RequiredCapabilities = 6,
}

impl TryFrom<u16> for ExtensionType {
    type Error = tls_codec::Error;

    /// Get the [`ExtensionType`] from a u16.
    /// Returns an error if the extension type is not known.
    /// Note that this returns a [`tls_codec::Error`](`tls_codec::Error`).
    fn try_from(a: u16) -> Result<Self, Self::Error> {
        match a {
            0 => Ok(ExtensionType::Reserved),
            1 => Ok(ExtensionType::Capabilities),
            2 => Ok(ExtensionType::Lifetime),
            3 => Ok(ExtensionType::KeyId),
            4 => Ok(ExtensionType::ParentHash),
            5 => Ok(ExtensionType::RatchetTree),
            _ => Err(tls_codec::Error::DecodingError(format!(
                "{} is an unkown extension type",
                a
            ))),
        }
    }
}

impl ExtensionType {
    /// Check whether an extension type is supported or not.
    pub fn is_supported(&self) -> bool {
        match self {
            ExtensionType::Reserved
            | ExtensionType::Capabilities
            | ExtensionType::Lifetime
            | ExtensionType::KeyId
            | ExtensionType::ParentHash
            | ExtensionType::RatchetTree
            | ExtensionType::RequiredCapabilities => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// An extension can be one of the following elements.
pub enum Extension {
    /// A [`CapabilitiesExtension`]
    Capabilities(CapabilitiesExtension),

    /// A [`KeyIdExtension`]
    KeyPackageId(KeyIdExtension),

    /// A [`LifetimeExtension`]
    LifeTime(LifetimeExtension),

    /// A [`ParentHashExtension`]
    ParentHash(ParentHashExtension),

    /// A [`RatchetTreeExtension`]
    RatchetTree(RatchetTreeExtension),

    /// A [`RequiredCapabilitiesExtension`]
    RequiredCapabilities(RequiredCapabilitiesExtension),
}

impl tls_codec::Size for Extension {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        2 /* extension type len */
        + 4 /* u32 len */ +
        match self {
            Extension::Capabilities(e) => e.tls_serialized_len(),
            Extension::KeyPackageId(e) => e.tls_serialized_len(),
            Extension::LifeTime(e) => e.tls_serialized_len(),
            Extension::ParentHash(e) => e.tls_serialized_len(),
            Extension::RatchetTree(e) => e.tls_serialized_len(),
            Extension::RequiredCapabilities(e) => e.tls_serialized_len(),
        }
    }
}

impl tls_codec::Serialize for Extension {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // First write the extension type.
        let written = self.extension_type().tls_serialize(writer)?;

        // Now serialize the extension into a separate byte vector.
        let extension_data_len = self.tls_serialized_len() - 6 /* extension type length and u32 length */;
        let mut extension_data = Vec::with_capacity(extension_data_len);

        let extension_data_written = match self {
            Extension::Capabilities(e) => e.tls_serialize(&mut extension_data),
            Extension::KeyPackageId(e) => e.tls_serialize(&mut extension_data),
            Extension::LifeTime(e) => e.tls_serialize(&mut extension_data),
            Extension::ParentHash(e) => e.tls_serialize(&mut extension_data),
            Extension::RatchetTree(e) => e.tls_serialize(&mut extension_data),
            Extension::RequiredCapabilities(e) => e.tls_serialize(&mut extension_data),
        }?;
        debug_assert_eq!(extension_data_written, extension_data_len);
        debug_assert_eq!(extension_data_written, extension_data.len());

        // Write the serialized extension out.
        TlsSliceU32(&extension_data)
            .tls_serialize(writer)
            .map(|l| l + written)
    }
}

impl tls_codec::Deserialize for Extension {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // Read the extension type and extension data.
        let extension_type = ExtensionType::tls_deserialize(bytes)?;
        let extension_data = TlsByteVecU32::tls_deserialize(bytes)?;

        // Now deserialize the extension itself from the extension data.
        let mut extension_data = extension_data.as_slice();
        Ok(match extension_type {
            ExtensionType::Capabilities => Extension::Capabilities(
                CapabilitiesExtension::tls_deserialize(&mut extension_data)?,
            ),
            ExtensionType::KeyId => {
                Extension::KeyPackageId(KeyIdExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::Lifetime => {
                Extension::LifeTime(LifetimeExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::ParentHash => {
                Extension::ParentHash(ParentHashExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::RatchetTree => {
                Extension::RatchetTree(RatchetTreeExtension::tls_deserialize(&mut extension_data)?)
            }
            ExtensionType::RequiredCapabilities => Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::tls_deserialize(&mut extension_data)?,
            ),
            ExtensionType::Reserved => {
                return Err(tls_codec::Error::DecodingError(format!(
                    "{:?} is not a valid extension type",
                    extension_type
                )))
            }
        })
    }
}

impl Extension {
    /// Get a reference to the `RatchetTreeExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `RatchetTreeExtension`.
    pub fn as_ratchet_tree_extension(&self) -> Result<&RatchetTreeExtension, ExtensionError> {
        match self {
            Self::RatchetTree(rte) => Ok(rte),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a RatchetTreeExtension".into(),
            )),
        }
    }

    /// Get a reference to the `LifetimeExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `LifetimeExtension`.
    pub fn as_lifetime_extension(&self) -> Result<&LifetimeExtension, ExtensionError> {
        match self {
            Self::LifeTime(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a LifetimeExtension".into(),
            )),
        }
    }

    /// Get a reference to the `KeyIDExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `KeyIDExtension`.
    pub fn as_key_id_extension(&self) -> Result<&KeyIdExtension, ExtensionError> {
        match self {
            Self::KeyPackageId(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a KeyIDExtension".into(),
            )),
        }
    }

    /// Get a reference to the `CapabilitiesExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `CapabilitiesExtension`.
    pub fn as_capabilities_extension(&self) -> Result<&CapabilitiesExtension, ExtensionError> {
        match self {
            Self::Capabilities(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a CapabilitiesExtension".into(),
            )),
        }
    }

    /// Get a reference to the `ParentHashExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `ParentHashExtension`.
    pub fn as_parent_hash_extension(&self) -> Result<&ParentHashExtension, ExtensionError> {
        match self {
            Self::ParentHash(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a ParentHashExtension".into(),
            )),
        }
    }

    /// Get a reference to the `RequiredCapabilitiesExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `RequiredCapabilitiesExtension`.
    pub fn as_required_capabilities_extension(
        &self,
    ) -> Result<&RequiredCapabilitiesExtension, ExtensionError> {
        match self {
            Self::RequiredCapabilities(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a RequiredCapabilitiesExtension".into(),
            )),
        }
    }

    #[inline]
    pub const fn extension_type(&self) -> ExtensionType {
        match self {
            Extension::Capabilities(_) => ExtensionType::Capabilities,
            Extension::KeyPackageId(_) => ExtensionType::KeyId,
            Extension::LifeTime(_) => ExtensionType::Lifetime,
            Extension::ParentHash(_) => ExtensionType::ParentHash,
            Extension::RatchetTree(_) => ExtensionType::RatchetTree,
            Extension::RequiredCapabilities(_) => ExtensionType::RequiredCapabilities,
        }
    }
}

impl Eq for Extension {}

impl PartialOrd for Extension {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.extension_type().partial_cmp(&other.extension_type())
    }
}

impl Ord for Extension {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.extension_type().cmp(&other.extension_type())
    }
}
