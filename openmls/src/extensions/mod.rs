//! # Extensions
//!
//! In MLS, extensions appear in the following places:
//! - In [`KeyPackages`](`crate::key_packages`), to describe client capabilities and aspects of their
//!   participation in the group.
//! - In the `GroupInfo`, to tell new members of a group what parameters are
//!   being used by the group, and to provide any additional details required
//!   to join the group.
//! - In the `GroupContext` object, to ensure that all members of the group
//!   have the same view of the parameters in use.
//!
//! Note that `GroupInfo` and `GroupContext` are not exposed in OpenMLS' public
//! API.
//!
//! OpenMLS supports the following extensions:
//!
//! - [`CapabilitiesExtension`] (KeyPackage extension)
//! - [`ExternalKeyIdExtension`] (KeyPackage extension)
//! - [`LifetimeExtension`] (KeyPackage extension)
//! - [`ParentHashExtension`] (KeyPackage extension)
//! - [`RatchetTreeExtension`] (GroupInfo extension)
//! - [`RequiredCapabilitiesExtension`] (GroupContext extension)

use openmls_traits::crypto::OpenMlsCrypto;
use serde::{Deserialize, Serialize};
use std::{
    convert::TryFrom,
    fmt::Debug,
    io::{Read, Write},
};
use tls_codec::*;

// Private
mod capabilities_extension;
mod external_key_id_extension;
mod life_time_extension;
mod parent_hash_extension;
mod ratchet_tree_extension;
mod required_capabilities;
use errors::*;

// Public
pub mod errors;

// Public re-exports
pub use capabilities_extension::CapabilitiesExtension;
pub use external_key_id_extension::ExternalKeyIdExtension;
pub use life_time_extension::LifetimeExtension;
pub use parent_hash_extension::ParentHashExtension;
pub use ratchet_tree_extension::RatchetTreeExtension;
pub use required_capabilities::RequiredCapabilitiesExtension;

use crate::treesync::node::Node;

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
#[allow(missing_docs)]
pub enum ExtensionType {
    /// Reserved. This must not be used.
    Reserved = 0,

    /// The capabilities extension indicates what protocol versions, ciphersuites,
    /// protocol extensions, and non-default proposal types are supported by a
    /// client.
    Capabilities = 1,

    /// The lifetime extension represents the times between which clients will
    /// consider a KeyPackage valid.
    Lifetime = 2,

    /// The external key id extension allows applications to add an explicit,
    /// application-defined identifier to a KeyPackage.
    ExternalKeyId = 3,

    /// The parent hash extension carries information to authenticate the
    /// structure of the tree, as described below.
    ParentHash = 4,

    /// The ratchet tree extensions provides the whole public state of the ratchet
    /// tree.
    RatchetTree = 5,

    /// The required capabilities extension defines the configuration of a group
    /// that imposes certain requirements on clients in the group.
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
            3 => Ok(ExtensionType::ExternalKeyId),
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
    /// Check whether an [`ExtensionType`] is supported or not.
    pub fn is_supported(&self) -> bool {
        match self {
            ExtensionType::Reserved
            | ExtensionType::Capabilities
            | ExtensionType::Lifetime
            | ExtensionType::ExternalKeyId
            | ExtensionType::ParentHash
            | ExtensionType::RatchetTree
            | ExtensionType::RequiredCapabilities => true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// # Extension
///
/// An extension is one of the [`Extension`] enum values.
/// The enum provides a set of common functionality for all extensions.
///
/// See the individual extensions for more details on each extension.
pub enum Extension {
    /// A [`CapabilitiesExtension`]
    Capabilities(CapabilitiesExtension),

    /// An [`ExternalKeyIdExtension`]
    ExternalKeyId(ExternalKeyIdExtension),

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
            Extension::ExternalKeyId(e) => e.tls_serialized_len(),
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
            Extension::ExternalKeyId(e) => e.tls_serialize(&mut extension_data),
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
            ExtensionType::ExternalKeyId => Extension::ExternalKeyId(
                ExternalKeyIdExtension::tls_deserialize(&mut extension_data)?,
            ),
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
    /// Get a reference to this extension as [`RatchetTreeExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] if called on
    /// an [`Extension`] that's not a [`RatchetTreeExtension`].
    pub fn as_ratchet_tree_extension(&self) -> Result<&RatchetTreeExtension, ExtensionError> {
        match self {
            Self::RatchetTree(rte) => Ok(rte),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a RatchetTreeExtension".into(),
            )),
        }
    }

    /// Get a reference to this extension as [`LifetimeExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] if called on an
    /// [`Extension`] that's not a [`LifetimeExtension`].
    pub fn as_lifetime_extension(&self) -> Result<&LifetimeExtension, ExtensionError> {
        match self {
            Self::LifeTime(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a LifetimeExtension".into(),
            )),
        }
    }

    /// Get a reference to this extension as [`ExternalKeyIdExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] if called on an
    /// [`Extension`] that's not an [`ExternalKeyIdExtension`].
    pub fn as_external_key_id_extension(&self) -> Result<&ExternalKeyIdExtension, ExtensionError> {
        match self {
            Self::ExternalKeyId(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not an ExternalKeyIdExtension".into(),
            )),
        }
    }

    /// Get a reference to this extension as [`CapabilitiesExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] error if called on an
    /// [`Extension`] that's not a [`CapabilitiesExtension`].
    pub fn as_capabilities_extension(&self) -> Result<&CapabilitiesExtension, ExtensionError> {
        match self {
            Self::Capabilities(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a CapabilitiesExtension".into(),
            )),
        }
    }

    /// Get a reference to this extension as [`ParentHashExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] error if called on an
    /// [`Extension`] that's not a [`ParentHashExtension`].
    pub fn as_parent_hash_extension(&self) -> Result<&ParentHashExtension, ExtensionError> {
        match self {
            Self::ParentHash(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a ParentHashExtension".into(),
            )),
        }
    }

    /// Get a reference to this extension as [`RequiredCapabilitiesExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] error if called on an
    /// [`Extension`] that's not a [`RequiredCapabilitiesExtension`].
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

    /// Returns the [`ExtensionType`]
    #[inline]
    pub const fn extension_type(&self) -> ExtensionType {
        match self {
            Extension::Capabilities(_) => ExtensionType::Capabilities,
            Extension::ExternalKeyId(_) => ExtensionType::ExternalKeyId,
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

/// This function tries to extract a vector of nodes from the given slice of
/// [`Extension`]s.
///
/// Returns the vector of nodes if it finds one and `None` otherwise. Returns an
/// error if there is either no [`RatchetTreeExtension`] or more than one.
pub(crate) fn try_nodes_from_extensions(
    other_extensions: &[Extension],
    crypto_backend: &impl OpenMlsCrypto,
) -> Result<Option<Vec<Option<Node>>>, ExtensionError> {
    let mut ratchet_tree_extensions = other_extensions
        .iter()
        .filter(|e| e.extension_type() == ExtensionType::RatchetTree);

    let nodes = match ratchet_tree_extensions.next() {
        Some(e) => {
            let mut nodes: Vec<Option<Node>> = e.as_ratchet_tree_extension()?.as_slice().into();
            // Compute the key package references.
            for node in nodes.iter_mut().flatten() {
                if let Node::LeafNode(leaf) = node {
                    leaf.set_key_package_ref(crypto_backend)?;
                }
            }
            Some(nodes)
        }
        None => None,
    };

    if ratchet_tree_extensions.next().is_some() {
        // Throw an error if there is more than one ratchet tree extension.
        // This shouldn't be the case anyway, because extensions are checked
        // for uniqueness when decoding them. We have to see if this makes
        // problems later as it's not something required by the spec right
        // now (Note issue #530 of the MLS spec.).
        return Err(ExtensionError::DuplicateRatchetTreeExtension);
    };

    Ok(nodes)
}
