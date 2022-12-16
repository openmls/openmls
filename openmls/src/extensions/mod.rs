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
//! - [`ApplicationIdExtension`] (KeyPackage extension)
//! - [`RatchetTreeExtension`] (GroupInfo extension)
//! - [`RequiredCapabilitiesExtension`] (GroupContext extension)
//! - [`ExternalPubExtension`] (GroupInfo extension)
//! - [`CapabilitiesExtension`] (KeyPackage extension)
//! - [`LifetimeExtension`] (KeyPackage extension)

use serde::{Deserialize, Serialize};
use std::{convert::TryFrom, fmt::Debug};
use tls_codec::*;

// Private
mod application_id_extension;
mod codec;
mod external_pub_extension;
mod external_sender_extension;
mod life_time_extension;
mod ratchet_tree_extension;
mod required_capabilities;
use errors::*;

// Public
pub mod errors;

// Public re-exports
pub use application_id_extension::ApplicationIdExtension;
pub use external_pub_extension::ExternalPubExtension;
pub use external_sender_extension::ExternalSendersExtension;
pub use life_time_extension::LifetimeExtension;
pub use ratchet_tree_extension::RatchetTreeExtension;
pub use required_capabilities::RequiredCapabilitiesExtension;

use crate::treesync::node::Node;

#[cfg(test)]
mod test_extensions;

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
    /// The application id extension allows applications to add an explicit,
    /// application-defined identifier to a KeyPackage.
    ApplicationId = 1,

    /// The ratchet tree extensions provides the whole public state of the ratchet
    /// tree.
    RatchetTree = 2,

    /// The required capabilities extension defines the configuration of a group
    /// that imposes certain requirements on clients in the group.
    RequiredCapabilities = 3,

    /// To join a group via an External Commit, a new member needs a GroupInfo
    /// with an ExternalPub extension present in its extensions field.
    ExternalPub = 4,

    /// Group context extension that contains the credentials and signature keys
    /// of senders that are permitted to send external proposals to the group.
    ExternalSenders = 5,

    /// The lifetime extension represents the times between which clients will
    /// consider a KeyPackage valid.
    /// TODO(#819): This extension will be deleted.
    Lifetime = 0xff01,
}

impl TryFrom<u16> for ExtensionType {
    type Error = tls_codec::Error;

    /// Get the [`ExtensionType`] from a u16.
    /// Returns an error if the extension type is not known.
    /// Note that this returns a [`tls_codec::Error`](`tls_codec::Error`).
    fn try_from(a: u16) -> Result<Self, Self::Error> {
        match a {
            1 => Ok(ExtensionType::ApplicationId),
            2 => Ok(ExtensionType::RatchetTree),
            3 => Ok(ExtensionType::RequiredCapabilities),
            4 => Ok(ExtensionType::ExternalPub),
            5 => Ok(ExtensionType::ExternalSenders),
            0xff01 => Ok(ExtensionType::Lifetime),
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
            ExtensionType::ApplicationId
            | ExtensionType::RatchetTree
            | ExtensionType::RequiredCapabilities
            | ExtensionType::ExternalPub
            | ExtensionType::ExternalSenders
            | ExtensionType::Lifetime => true,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Extension {
    /// An [`ApplicationIdExtension`]
    ApplicationId(ApplicationIdExtension),

    /// A [`RatchetTreeExtension`]
    RatchetTree(RatchetTreeExtension),

    /// A [`RequiredCapabilitiesExtension`]
    RequiredCapabilities(RequiredCapabilitiesExtension),

    /// A [`ExternalPubExtension`]
    ExternalPub(ExternalPubExtension),

    /// A [`ExternalPubExtension`]
    ExternalSenders(ExternalSendersExtension),

    /// A [`LifetimeExtension`]
    /// TODO(#819): This extension will be deleted.
    Lifetime(LifetimeExtension),
}

impl Extension {
    /// Get a reference to this extension as [`ApplicationIdExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] if called on an
    /// [`Extension`] that's not an [`ApplicationIdExtension`].
    pub fn as_application_id_extension(&self) -> Result<&ApplicationIdExtension, ExtensionError> {
        match self {
            Self::ApplicationId(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not an ApplicationIdExtension".into(),
            )),
        }
    }

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

    /// Get a reference to this extension as [`ExternalPubExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] error if called on an
    /// [`Extension`] that's not a [`ExternalPubExtension`].
    pub fn as_external_pub_extension(&self) -> Result<&ExternalPubExtension, ExtensionError> {
        match self {
            Self::ExternalPub(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not an ExternalPubExtension".into(),
            )),
        }
    }

    /// Get a reference to this extension as [`ExternalSendersExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] error if called on an
    /// [`Extension`] that's not a [`ExternalSendersExtension`].
    pub fn as_external_senders_extension(
        &self,
    ) -> Result<&ExternalSendersExtension, ExtensionError> {
        match self {
            Self::ExternalSenders(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not an ExternalSendersExtension".into(),
            )),
        }
    }

    /// Get a reference to this extension as [`LifetimeExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] if called on an
    /// [`Extension`] that's not a [`LifetimeExtension`].
    pub fn as_lifetime_extension(&self) -> Result<&LifetimeExtension, ExtensionError> {
        match self {
            Self::Lifetime(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not a LifetimeExtension".into(),
            )),
        }
    }

    /// Returns the [`ExtensionType`]
    #[inline]
    pub const fn extension_type(&self) -> ExtensionType {
        match self {
            Extension::ApplicationId(_) => ExtensionType::ApplicationId,
            Extension::RatchetTree(_) => ExtensionType::RatchetTree,
            Extension::RequiredCapabilities(_) => ExtensionType::RequiredCapabilities,
            Extension::ExternalPub(_) => ExtensionType::ExternalPub,
            Extension::ExternalSenders(_) => ExtensionType::ExternalSenders,
            Extension::Lifetime(_) => ExtensionType::Lifetime,
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
) -> Result<Option<Vec<Option<Node>>>, ExtensionError> {
    let mut ratchet_tree_extensions = other_extensions
        .iter()
        .filter(|e| e.extension_type() == ExtensionType::RatchetTree);

    let nodes = match ratchet_tree_extensions.next() {
        Some(e) => Some(e.as_ratchet_tree_extension()?.as_slice().into()),
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
