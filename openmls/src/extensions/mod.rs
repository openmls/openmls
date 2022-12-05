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
use std::{collections::HashSet, convert::TryFrom, fmt::Debug};
use tls_codec::*;

// Private
mod application_id_extension;
mod capabilities_extension;
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
pub use capabilities_extension::CapabilitiesExtension;
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

    /// The capabilities extension indicates what protocol versions, ciphersuites,
    /// protocol extensions, and non-default proposal types are supported by a
    /// client.
    /// TODO(#819): This extension will be deleted.
    Capabilities = 0xff00,

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
            0xff00 => Ok(ExtensionType::Capabilities),
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
            | ExtensionType::Capabilities
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

    /// A [`CapabilitiesExtension`]
    /// TODO(#819): This extension will be deleted.
    Capabilities(CapabilitiesExtension),

    /// A [`LifetimeExtension`]
    /// TODO(#819): This extension will be deleted.
    Lifetime(LifetimeExtension),
}

/// A list of extensions with unique extension types.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TlsSize, TlsSerialize, TlsDeserialize,
)]
pub struct Extensions {
    inner: Vec<Extension>,
}

impl Extensions {
    /// Create an extension list that is empty.
    pub fn empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// Create an extension list that contains a single extension.
    pub fn single(extension: Extension) -> Self {
        Self {
            inner: vec![extension],
        }
    }

    /// Create an extension list that contains multiple extensions.
    ///
    /// This function will fail when the list of extensions contains duplicate extension types.
    pub fn multi(extensions: Vec<Extension>) -> Result<Self, &'static str> {
        extensions.try_into()
    }

    // ---------------------------------------------------------------------------------------------

    /// Add an extension to the extension list.
    ///
    /// Returns an error when there already is an extension with the same extension type.
    pub fn add(&mut self, extension: Extension) -> Result<(), &'static str> {
        if !self.contains(extension.extension_type()) {
            self.inner.push(extension);
            Ok(())
        } else {
            Err("Cannot add duplicate extension.")
        }
    }

    /// Add an extension to the extension list (or silently replace an existing one.)
    pub fn add_or_replace(&mut self, extension: Extension) {
        let _ = self.remove(extension.extension_type());
        self.add(extension).unwrap();
    }

    /// Remove an extension from the extension list.
    ///
    /// Returns an error when there is no extension with the given extension type.
    pub fn remove(&mut self, extension_type: ExtensionType) -> Result<(), &'static str> {
        if self.contains(extension_type) {
            self.inner.retain(|e| e.extension_type() != extension_type);
            Ok(())
        } else {
            Err("Cannot remove non-existent extension.")
        }
    }

    /// Replace an extension in the extension list.
    ///
    /// Returns an error when there is no extension with the given extension type.
    #[cfg(any(feature = "test-utils", test))]
    pub fn replace(&mut self, extension: Extension) -> Result<(), &'static str> {
        if self.contains(extension.extension_type()) {
            self.remove(extension.extension_type()).unwrap();
            self.add(extension).unwrap();
            Ok(())
        } else {
            Err("Cannot replace non-existent extension.")
        }
    }

    // ---------------------------------------------------------------------------------------------

    /// Return true if the extension list contains the extension with the given type.
    pub fn contains(&self, extension_type: ExtensionType) -> bool {
        self.inner
            .iter()
            .any(|e| e.extension_type() == extension_type)
    }

    /// Check that the candidate extension list is valid.
    ///
    /// Valid means:
    ///
    /// * Does not contain duplicate extension types (ValSem012)
    pub fn validate(candidate: &[Extension]) -> bool {
        // We use a [`HashSet`] to identify duplicate extension types by ...
        let mut hash_map = HashSet::new();

        for extension_type in candidate.iter().map(Extension::extension_type) {
            // ... trying to insert every element ...
            if !hash_map.insert(extension_type) {
                // ... and returning false if an element of the same extension type was inserted before.
                return false;
            }
        }

        true
    }
}

impl TryFrom<Vec<Extension>> for Extensions {
    type Error = &'static str;

    fn try_from(value: Vec<Extension>) -> Result<Self, Self::Error> {
        if Extensions::validate(&value) {
            Ok(Self { inner: value })
        } else {
            Err("List of extensions must not contain duplicate extension types.")
        }
    }
}

impl Default for Extensions {
    fn default() -> Self {
        Self::empty()
    }
}

impl Extensions {
    /// Get a reference to the inner value.
    pub fn inner(&self) -> &Vec<Extension> {
        &self.inner
    }

    /// Get a reference to the [`ApplicationIdExtension`] if there is any.
    pub fn application_id(&self) -> Option<&ApplicationIdExtension> {
        // Safety: `.unwrap()` is safe here.
        self.inner
            .iter()
            .find(|e| e.extension_type() == ExtensionType::ApplicationId)
            .map(|e| e.as_application_id_extension().unwrap())
    }

    /// Get a reference to the [`RatchetTreeExtension`] if there is any.
    pub fn ratchet_tree(&self) -> Option<&RatchetTreeExtension> {
        // Safety: `.unwrap()` is safe here.
        self.inner
            .iter()
            .find(|e| e.extension_type() == ExtensionType::RatchetTree)
            .map(|e| e.as_ratchet_tree_extension().unwrap())
    }

    /// Get a reference to the [`RequiredCapabilitiesExtension`] if there is any.
    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        // Safety: `.unwrap()` is safe here.
        self.inner
            .iter()
            .find(|e| e.extension_type() == ExtensionType::RequiredCapabilities)
            .map(|e| e.as_required_capabilities_extension().unwrap())
    }

    /// Get a reference to the [`ExternalPubExtension`] if there is any.
    pub fn external_pub(&self) -> Option<&ExternalPubExtension> {
        // Safety: `.unwrap()` is safe here.
        self.inner
            .iter()
            .find(|e| e.extension_type() == ExtensionType::ExternalPub)
            .map(|e| e.as_external_pub_extension().unwrap())
    }

    /// Get a reference to the [`CapabilitiesExtension`] if there is any.
    pub fn capabilities(&self) -> Option<&CapabilitiesExtension> {
        // Safety: `.unwrap()` is safe here.
        self.inner
            .iter()
            .find(|e| e.extension_type() == ExtensionType::Capabilities)
            .map(|e| e.as_capabilities_extension().unwrap())
    }

    /// Get a reference to the [`LifetimeExtension`] if there is any.
    pub fn lifetime(&self) -> Option<&LifetimeExtension> {
        // Safety: `.unwrap()` is safe here.
        self.inner
            .iter()
            .find(|e| e.extension_type() == ExtensionType::Lifetime)
            .map(|e| e.as_lifetime_extension().unwrap())
    }
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
            Extension::Capabilities(_) => ExtensionType::Capabilities,
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

/// This function tries to extract a vector of nodes from the given [`Extensions`].
///
/// Returns the vector of nodes if it finds one and `None` otherwise.
pub(crate) fn try_nodes_from_extensions(
    other_extensions: &Extensions,
) -> Option<Vec<Option<Node>>> {
    other_extensions.ratchet_tree().map(|e| e.as_slice().into())
}

#[cfg(test)]
mod test {
    use crate::extensions::*;

    #[test]
    fn valsem012_add() {
        let mut extensions = Extensions::empty();
        extensions
            .add(Extension::Lifetime(LifetimeExtension::new(42)))
            .unwrap();
        assert!(extensions
            .add(Extension::Lifetime(LifetimeExtension::new(1337)))
            .is_err());
    }

    #[test]
    fn valsem012_multi_and_try_from() {
        let tests = [
            (vec![], true),
            (vec![Extension::Lifetime(LifetimeExtension::new(0))], true),
            (
                vec![
                    Extension::Lifetime(LifetimeExtension::new(0)),
                    Extension::Lifetime(LifetimeExtension::new(1)),
                ],
                false,
            ),
            (
                vec![
                    Extension::Lifetime(LifetimeExtension::new(0)),
                    Extension::Lifetime(LifetimeExtension::new(1)),
                    Extension::Lifetime(LifetimeExtension::new(2)),
                ],
                false,
            ),
            (
                vec![
                    Extension::Lifetime(LifetimeExtension::new(0)),
                    Extension::Capabilities(CapabilitiesExtension::default()),
                ],
                true,
            ),
            (
                vec![
                    Extension::Lifetime(LifetimeExtension::new(0)),
                    Extension::Lifetime(LifetimeExtension::new(1)),
                    Extension::Capabilities(CapabilitiesExtension::default()),
                ],
                false,
            ),
            (
                vec![
                    Extension::Lifetime(LifetimeExtension::new(0)),
                    Extension::Capabilities(CapabilitiesExtension::default()),
                    Extension::Capabilities(CapabilitiesExtension::default()),
                ],
                false,
            ),
        ];

        for (test, expected) in tests.into_iter() {
            match Extensions::multi(test.clone()) {
                Ok(_) => assert!(expected),
                Err(_) => assert!(!expected),
            }

            match Extensions::try_from(test) {
                Ok(_) => assert!(expected),
                Err(_) => assert!(!expected),
            }
        }
    }
}
