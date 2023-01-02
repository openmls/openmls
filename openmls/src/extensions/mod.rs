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

use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, convert::TryFrom, fmt::Debug};
use tls_codec::*;

// Private
mod application_id_extension;
mod codec;
mod external_pub_extension;
mod external_sender_extension;
mod ratchet_tree_extension;
mod required_capabilities;
use errors::*;

// Public
pub mod errors;

// Public re-exports
pub use application_id_extension::ApplicationIdExtension;
pub use external_pub_extension::ExternalPubExtension;
pub use external_sender_extension::ExternalSendersExtension;
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
            | ExtensionType::ExternalSenders => true,
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
    pub fn multi(extensions: Vec<Extension>) -> Result<Self, InvalidExtensionError> {
        extensions.try_into()
    }

    // ---------------------------------------------------------------------------------------------

    /// Add an extension to the extension list.
    ///
    /// Returns an error when there already is an extension with the same extension type.
    pub fn add(&mut self, extension: Extension) -> Result<(), InvalidExtensionError> {
        if !self.contains(extension.extension_type()) {
            self.inner.push(extension);
            Ok(())
        } else {
            Err(InvalidExtensionError::Duplicate)
        }
    }

    /// Add an extension to the extension list (or replace an existing one.)
    ///
    /// Returns the replaced extension (if any).
    pub fn add_or_replace(&mut self, extension: Extension) -> Option<Extension> {
        let replaced = self.remove(extension.extension_type()).ok();
        self.inner.push(extension);
        replaced
    }

    /// Remove an extension from the extension list.
    ///
    /// Returns the removed extension or an error when there is no extension with the given extension type.
    pub fn remove(
        &mut self,
        extension_type: ExtensionType,
    ) -> Result<Extension, InvalidExtensionError> {
        match self
            .inner
            .iter()
            .position(|e| e.extension_type() == extension_type)
        {
            Some(position) => Ok(self.inner.remove(position)),
            None => Err(InvalidExtensionError::NotFound),
        }
    }

    /// Replace an extension in the extension list.
    ///
    /// Returns the replaced extension or an error when there is no extension with the given extension type.
    #[cfg(any(feature = "test-utils", test))]
    pub fn replace(&mut self, extension: Extension) -> Result<Extension, InvalidExtensionError> {
        let mut extension = extension;

        match self
            .inner
            .iter()
            .position(|e| e.extension_type() == extension.extension_type())
        {
            Some(position) => {
                std::mem::swap(&mut self.inner[position], &mut extension);
                Ok(extension)
            }
            None => Err(InvalidExtensionError::NotFound),
        }
    }

    // ---------------------------------------------------------------------------------------------

    /// Return true if (and only if) the extension list contains the extension with the given type.
    pub fn contains(&self, extension_type: ExtensionType) -> bool {
        self.inner
            .iter()
            .any(|e| e.extension_type() == extension_type)
    }

    /// Check that the candidate extension list is valid.
    ///
    /// Specifically, the candidate list must ...
    ///
    /// * ... not contain duplicate extension types (ValSem012) ...
    ///
    /// ... to be valid.
    pub fn validate(candidate: &[Extension]) -> Result<(), InvalidExtensionError> {
        let mut map = BTreeSet::new();

        // We iterate over all extensions ...
        for extension_type in candidate.iter().map(Extension::extension_type) {
            // ... and try to insert the extension type into our set.
            if !map.insert(extension_type) {
                // When insert returns false, an element of the same extension type was inserted
                // before, which means that we found a duplicate.
                return Err(InvalidExtensionError::Duplicate);
            }
        }

        Ok(())
    }
}

impl Default for Extensions {
    fn default() -> Self {
        Self::empty()
    }
}

impl TryFrom<Vec<Extension>> for Extensions {
    type Error = InvalidExtensionError;

    fn try_from(value: Vec<Extension>) -> Result<Self, Self::Error> {
        Extensions::validate(&value)?;

        Ok(Self { inner: value })
    }
}

impl Extensions {
    /// Get a reference to the [`ApplicationIdExtension`] if there is any.
    pub fn application_id(&self) -> Option<&ApplicationIdExtension> {
        for extension in self.inner.iter() {
            if let Extension::ApplicationId(ext) = extension {
                return Some(ext);
            }
        }

        None
    }

    /// Get a reference to the [`RatchetTreeExtension`] if there is any.
    pub fn ratchet_tree(&self) -> Option<&RatchetTreeExtension> {
        for extension in self.inner.iter() {
            if let Extension::RatchetTree(ext) = extension {
                return Some(ext);
            }
        }

        None
    }

    /// Get a reference to the [`RequiredCapabilitiesExtension`] if there is any.
    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        for extension in self.inner.iter() {
            if let Extension::RequiredCapabilities(ext) = extension {
                return Some(ext);
            }
        }

        None
    }

    /// Get a reference to the [`ExternalPubExtension`] if there is any.
    pub fn external_pub(&self) -> Option<&ExternalPubExtension> {
        for extension in self.inner.iter() {
            if let Extension::ExternalPub(ext) = extension {
                return Some(ext);
            }
        }

        None
    }

    /// Get a reference to the [`ExternalSendersExtension`] if there is any.
    pub fn external_senders(&self) -> Option<&ExternalSendersExtension> {
        for extension in self.inner.iter() {
            if let Extension::ExternalSenders(ext) = extension {
                return Some(ext);
            }
        }

        None
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

    /// Returns the [`ExtensionType`]
    #[inline]
    pub const fn extension_type(&self) -> ExtensionType {
        match self {
            Extension::ApplicationId(_) => ExtensionType::ApplicationId,
            Extension::RatchetTree(_) => ExtensionType::RatchetTree,
            Extension::RequiredCapabilities(_) => ExtensionType::RequiredCapabilities,
            Extension::ExternalPub(_) => ExtensionType::ExternalPub,
            Extension::ExternalSenders(_) => ExtensionType::ExternalSenders,
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

#[cfg(test)]
mod test {
    use crate::extensions::*;

    #[test]
    fn add() {
        let mut extensions = Extensions::empty();
        extensions
            .add(Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::default(),
            ))
            .unwrap();
        assert!(extensions
            .add(Extension::RequiredCapabilities(
                RequiredCapabilitiesExtension::default()
            ))
            .is_err());
    }

    #[test]
    fn add_multi_and_try_from() {
        // Create two extensions with different extension types.
        let x = Extension::ApplicationId(ApplicationIdExtension::new(b"Test"));
        let y = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::default());

        let tests = [
            (vec![], true),
            (vec![x.clone()], true),
            (vec![x.clone(), x.clone()], false),
            (vec![x.clone(), x.clone(), x.clone()], false),
            (vec![y.clone()], true),
            (vec![y.clone(), y.clone()], false),
            (vec![y.clone(), y.clone(), y.clone()], false),
            (vec![x.clone(), y.clone()], true),
            (vec![y.clone(), x.clone()], true),
            (vec![x.clone(), x.clone(), y.clone()], false),
            (vec![y.clone(), y.clone(), x.clone()], false),
            (vec![x.clone(), y.clone(), y.clone()], false),
            (vec![y.clone(), x.clone(), x.clone()], false),
            (vec![x.clone(), y.clone(), x.clone()], false),
            (vec![y.clone(), x, y], false),
        ];

        for (test, should_work) in tests.into_iter() {
            // Test `add`.
            {
                let mut extensions = Extensions::empty();

                let mut works = true;
                for ext in test.iter() {
                    match extensions.add(ext.clone()) {
                        Ok(_) => {}
                        Err(InvalidExtensionError::Duplicate) => {
                            works = false;
                        }
                        _ => panic!("This should have never happened."),
                    }
                }

                println!("{:?}, {:?}", test.clone(), should_work);
                assert_eq!(works, should_work);
            }

            // Test `multi` and `try_from`.
            if should_work {
                assert!(Extensions::multi(test.clone()).is_ok());
                assert!(Extensions::try_from(test).is_ok());
            } else {
                assert!(Extensions::multi(test.clone()).is_err());
                assert!(Extensions::try_from(test).is_err());
            }
        }
    }
}
