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
    convert::Infallible,
    fmt::Debug,
    io::{Read, Write},
    marker::PhantomData,
};

use serde::{Deserialize, Serialize};

// Private
#[cfg(feature = "extensions-draft-08")]
mod app_data_dict_extension;
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
#[cfg(feature = "extensions-draft-08")]
pub use app_data_dict_extension::{AppDataDictionary, AppDataDictionaryExtension};
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
    Size, TlsDeserialize, TlsSerialize, TlsSize,
};

use crate::{
    group::GroupContext, key_packages::KeyPackage, messages::group_info::GroupInfo,
    treesync::LeafNode,
};

#[cfg(test)]
mod tests;

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

    #[cfg(feature = "extensions-draft-08")]
    /// AppDataDictionary extension
    AppDataDictionary,

    /// A GREASE extension type for ensuring extensibility.
    Grease(u16),

    /// A currently unknown extension type.
    Unknown(u16),
}

impl ExtensionType {
    /// Returns true for all extension types that are considered "default" by the spec.
    pub(crate) fn is_default(self) -> bool {
        match self {
            ExtensionType::ApplicationId
            | ExtensionType::RatchetTree
            | ExtensionType::RequiredCapabilities
            | ExtensionType::ExternalPub
            | ExtensionType::ExternalSenders => true,
            ExtensionType::LastResort | ExtensionType::Grease(_) | ExtensionType::Unknown(_) => {
                false
            }
            #[cfg(feature = "extensions-draft-08")]
            ExtensionType::AppDataDictionary => false,
        }
    }

    /// Returns whether an extension type is valid when used in leaf nodes.
    /// Returns None if validity can not be determined.
    /// This is the case for unknown extensions.
    //  https://validation.openmls.tech/#valn1601
    pub(crate) fn is_valid_in_leaf_node(self) -> bool {
        match self {
            ExtensionType::Grease(_)
            | ExtensionType::LastResort
            | ExtensionType::RatchetTree
            | ExtensionType::RequiredCapabilities
            | ExtensionType::ExternalPub
            | ExtensionType::ExternalSenders => false,
            ExtensionType::Unknown(_) | ExtensionType::ApplicationId => true,
            #[cfg(feature = "extensions-draft-08")]
            ExtensionType::AppDataDictionary => true,
        }
    }
    pub(crate) fn is_valid_in_group_info(self) -> Option<bool> {
        match self {
            ExtensionType::Grease(_)
            | ExtensionType::LastResort
            | ExtensionType::RequiredCapabilities
            | ExtensionType::ExternalSenders
            | ExtensionType::ApplicationId => Some(false),
            ExtensionType::RatchetTree | ExtensionType::ExternalPub => Some(true),
            ExtensionType::Unknown(_) => None,
            #[cfg(feature = "extensions-draft-08")]
            ExtensionType::AppDataDictionary => Some(true),
        }
    }

    pub(crate) fn is_valid_in_group_context(self) -> bool {
        match self {
            ExtensionType::RequiredCapabilities
            | ExtensionType::ExternalSenders
            | ExtensionType::Unknown(_) => true,
            #[cfg(feature = "extensions-draft-08")]
            ExtensionType::AppDataDictionary => true,
            _ => false,
        }
    }

    /// Returns true if this is a GREASE extension type.
    ///
    /// GREASE values are used to ensure implementations properly handle unknown
    /// extension types. See [RFC 9420 Section 13.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-13.5).
    pub fn is_grease(&self) -> bool {
        matches!(self, ExtensionType::Grease(_))
    }
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
            #[cfg(feature = "extensions-draft-08")]
            6 => ExtensionType::AppDataDictionary,
            10 => ExtensionType::LastResort,
            unknown if crate::grease::is_grease_value(unknown) => ExtensionType::Grease(unknown),
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
            #[cfg(feature = "extensions-draft-08")]
            ExtensionType::AppDataDictionary => 6,
            ExtensionType::LastResort => 10,
            ExtensionType::Grease(value) => value,
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

    /// An [`AppDataDictionaryExtension`]
    #[cfg(feature = "extensions-draft-08")]
    AppDataDictionary(AppDataDictionaryExtension),

    /// A [`LastResortExtension`]
    LastResort(LastResortExtension),

    /// A currently unknown extension.
    Unknown(u16, UnknownExtension),
}

/// A unknown/unparsed extension represented by raw bytes.
#[derive(
    PartialEq, Eq, Clone, Debug, Serialize, Deserialize, TlsSize, TlsSerialize, TlsDeserialize,
)]
pub struct UnknownExtension(pub Vec<u8>);

/// A Extension for Object of type T
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extensions<T> {
    unique: Vec<Extension>,
    #[serde(skip)]
    _object: core::marker::PhantomData<T>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, TlsSize, TlsSerialize, TlsDeserialize)]
/// Any object
pub struct AnyObject;

impl<T> Default for Extensions<T> {
    fn default() -> Self {
        Self {
            unique: vec![],
            _object: PhantomData,
        }
    }
}

impl<T> Size for Extensions<T> {
    fn tls_serialized_len(&self) -> usize {
        Vec::tls_serialized_len(&self.unique)
    }
}

impl<T> TlsSerializeTrait for Extensions<T> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        self.unique.tls_serialize(writer)
    }
}

impl<T: ExtensionValidator> TlsDeserializeTrait for Extensions<T>
where
    InvalidExtensionError: From<T::Error>,
{
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let candidate: Vec<Extension> = Vec::tls_deserialize(bytes)?;
        Extensions::<T>::try_from(candidate)
            .map_err(|_| Error::DecodingError("Found duplicate extensions".into()))
    }
}

impl<T: ExtensionValidator> DeserializeBytes for Extensions<T>
where
    InvalidExtensionError: From<T::Error>,
{
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let extensions = Extensions::<T>::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[extensions.tls_serialized_len()..];
        Ok((extensions, remainder))
    }
}

impl<T: ExtensionValidator> Extensions<T> {
    /// Create an empty extension list.
    pub fn empty() -> Self {
        Self {
            unique: vec![],
            _object: PhantomData,
        }
    }

    /// Returns an iterator over the extension list.
    pub fn iter(&self) -> impl Iterator<Item = &Extension> {
        self.unique.iter()
    }

    /// Remove an extension from the extension list.
    ///
    /// Returns the removed extension or `None` when there is no extension with
    /// the given extension type.
    pub fn remove(&mut self, extension_type: ExtensionType) -> Option<Extension> {
        if let Some(pos) = self
            .unique
            .iter()
            .position(|ext| ext.extension_type() == extension_type)
        {
            Some(self.unique.remove(pos))
        } else {
            None
        }
    }

    /// Returns `true` iff the extension list contains an extension with the
    /// given extension type.
    pub fn contains(&self, extension_type: ExtensionType) -> bool {
        self.unique
            .iter()
            .any(|ext| ext.extension_type() == extension_type)
    }
}

impl<T> Extensions<T>
where
    T: ExtensionValidator,
    InvalidExtensionError: From<T::Error>,
{
    /// Create an extension list with a single extension.
    pub fn single(extension: Extension) -> Result<Self, InvalidExtensionError> {
        T::validate_extension_type(&extension)?;
        Ok(Self {
            unique: vec![extension],
            _object: PhantomData,
        })
    }

    /// Create an extension list with multiple extensions.
    ///
    /// This function will fail when the list of extensions contains duplicate
    /// extension types.
    pub fn from_vec(extensions: Vec<Extension>) -> Result<Self, InvalidExtensionError> {
        extensions.try_into()
    }

    /// Validate if the extensions are valid for this context
    pub fn validate<'a>(
        extensions: impl Iterator<Item = &'a Extension>,
    ) -> Result<(), InvalidExtensionError> {
        for ext in extensions {
            T::validate_extension_type(ext)?;
        }
        Ok(())
    }

    /// Add an extension to the extension list.
    ///
    /// Returns an error when there already is an extension with the same
    /// extension type.
    pub fn add(&mut self, extension: Extension) -> Result<(), InvalidExtensionError> {
        T::validate_extension_type(&extension)?;
        if self.contains(extension.extension_type()) {
            return Err(InvalidExtensionError::Duplicate);
        }

        self.unique.push(extension);

        Ok(())
    }

    /// Add an extension to the extension list (or replace an existing one.)
    ///
    /// Returns the replaced extension (if any).
    pub fn add_or_replace(
        &mut self,
        extension: Extension,
    ) -> Result<Option<Extension>, InvalidExtensionError> {
        T::validate_extension_type(&extension)?;
        let replaced = self.remove(extension.extension_type());
        self.unique.push(extension);
        Ok(replaced)
    }
}

/// Can be implemented by a type to validate extensions.
pub trait ExtensionValidator {
    /// The error returned by the validator
    type Error;

    /// Check if the extension is valid.
    fn validate_extension_type(ext: &Extension) -> Result<(), Self::Error>;
}

impl ExtensionValidator for AnyObject {
    type Error = Infallible;

    fn validate_extension_type(_ext: &Extension) -> Result<(), Infallible> {
        Ok(())
    }
}

impl<T: ExtensionValidator> TryFrom<Vec<Extension>> for Extensions<T>
where
    InvalidExtensionError: From<T::Error>,
{
    type Error = InvalidExtensionError;

    fn try_from(candidate: Vec<Extension>) -> Result<Self, Self::Error> {
        let mut unique: Vec<Extension> = Vec::new();
        for extension in candidate.into_iter() {
            T::validate_extension_type(&extension)?;

            if unique
                .iter()
                .any(|ext| ext.extension_type() == extension.extension_type())
            {
                return Err(InvalidExtensionError::Duplicate);
            } else {
                unique.push(extension);
            }
        }

        Ok(Self {
            unique,
            _object: PhantomData,
        })
    }
}

// https://validation.openmls.tech/#valn1602
impl ExtensionValidator for GroupInfo {
    type Error = ExtensionTypeNotValidInGroupInfoError;

    fn validate_extension_type(
        ext: &Extension,
    ) -> Result<(), ExtensionTypeNotValidInGroupInfoError> {
        if ext.extension_type().is_valid_in_group_info() == Some(true)
            || ext.extension_type().is_valid_in_group_info().is_none()
        {
            Ok(())
        } else {
            Err(ExtensionTypeNotValidInGroupInfoError(ext.extension_type()))
        }
    }
}

// https://validation.openmls.tech/#valn1603
impl ExtensionValidator for GroupContext {
    type Error = ExtensionTypeNotValidInGroupContextError;

    fn validate_extension_type(
        ext: &Extension,
    ) -> Result<(), ExtensionTypeNotValidInGroupContextError> {
        if ext.extension_type().is_valid_in_group_context() {
            Ok(())
        } else {
            Err(ExtensionTypeNotValidInGroupContextError(
                ext.extension_type(),
            ))
        }
    }
}

// https://validation.openmls.tech/#valn1604
impl ExtensionValidator for KeyPackage {
    type Error = ExtensionTypeNotValidInKeyPackageError;

    fn validate_extension_type(
        ext: &Extension,
    ) -> Result<(), ExtensionTypeNotValidInKeyPackageError> {
        if ext.extension_type() == ExtensionType::LastResort
            || matches!(ext.extension_type(), ExtensionType::Unknown(_))
        {
            Ok(())
        } else {
            Err(ExtensionTypeNotValidInKeyPackageError(ext.extension_type()))
        }
    }
}

// https://validation.openmls.tech/#valn1601
impl ExtensionValidator for LeafNode {
    type Error = ExtensionTypeNotValidInLeafNodeError;

    fn validate_extension_type(
        ext: &Extension,
    ) -> Result<(), ExtensionTypeNotValidInLeafNodeError> {
        if ext.extension_type().is_valid_in_leaf_node() {
            Ok(())
        } else {
            Err(ExtensionTypeNotValidInLeafNodeError(ext.extension_type()))
        }
    }
}

impl<T> Extensions<T> {
    fn find_by_type(&self, extension_type: ExtensionType) -> Option<&Extension> {
        self.unique
            .iter()
            .find(|ext| ext.extension_type() == extension_type)
    }

    /// Get a reference to the [`ApplicationIdExtension`] if there is any.
    pub fn application_id(&self) -> Option<&ApplicationIdExtension> {
        self.find_by_type(ExtensionType::ApplicationId)
            .and_then(|e| match e {
                Extension::ApplicationId(e) => Some(e),
                _ => None,
            })
    }

    /// Get a reference to the [`RatchetTreeExtension`] if there is any.
    pub fn ratchet_tree(&self) -> Option<&RatchetTreeExtension> {
        self.find_by_type(ExtensionType::RatchetTree)
            .and_then(|e| match e {
                Extension::RatchetTree(e) => Some(e),
                _ => None,
            })
    }

    /// Get a reference to the [`RequiredCapabilitiesExtension`] if there is
    /// any.
    pub fn required_capabilities(&self) -> Option<&RequiredCapabilitiesExtension> {
        self.find_by_type(ExtensionType::RequiredCapabilities)
            .and_then(|e| match e {
                Extension::RequiredCapabilities(e) => Some(e),
                _ => None,
            })
    }

    /// Get a reference to the [`ExternalPubExtension`] if there is any.
    pub fn external_pub(&self) -> Option<&ExternalPubExtension> {
        self.find_by_type(ExtensionType::ExternalPub)
            .and_then(|e| match e {
                Extension::ExternalPub(e) => Some(e),
                _ => None,
            })
    }

    /// Get a reference to the [`ExternalSendersExtension`] if there is any.
    pub fn external_senders(&self) -> Option<&ExternalSendersExtension> {
        self.find_by_type(ExtensionType::ExternalSenders)
            .and_then(|e| match e {
                Extension::ExternalSenders(e) => Some(e),
                _ => None,
            })
    }

    #[cfg(feature = "extensions-draft-08")]
    /// Get a reference to the [`AppDataDictionaryExtension`] if there is any.
    pub fn app_data_dictionary(&self) -> Option<&AppDataDictionaryExtension> {
        self.find_by_type(ExtensionType::AppDataDictionary)
            .and_then(|e| match e {
                Extension::AppDataDictionary(e) => Some(e),
                _ => None,
            })
    }

    /// Get a reference to the [`UnknownExtension`] with the given type id, if there is any.
    pub fn unknown(&self, extension_type_id: u16) -> Option<&UnknownExtension> {
        let extension_type: ExtensionType = extension_type_id.into();

        match extension_type {
            ExtensionType::Unknown(_) => self.find_by_type(extension_type).and_then(|e| match e {
                Extension::Unknown(_, e) => Some(e),
                _ => None,
            }),
            _ => None,
        }
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
    #[cfg(feature = "extensions-draft-08")]
    /// Get a reference to this extension as [`AppDataDictionaryExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] if called on an
    /// [`Extension`] that's not an [`AppDataDictionaryExtension`].
    pub fn as_app_data_dictionary_extension(
        &self,
    ) -> Result<&AppDataDictionaryExtension, ExtensionError> {
        match self {
            Self::AppDataDictionary(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not an AppDataDictionaryExtension".into(),
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
    /// Returns an [`ExtensionError::InvalidExtensionType`] error if called on
    /// an [`Extension`] that's not a [`RequiredCapabilitiesExtension`].
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
    /// Returns an [`ExtensionError::InvalidExtensionType`] error if called on
    /// an [`Extension`] that's not a [`ExternalPubExtension`].
    pub fn as_external_pub_extension(&self) -> Result<&ExternalPubExtension, ExtensionError> {
        match self {
            Self::ExternalPub(e) => Ok(e),
            _ => Err(ExtensionError::InvalidExtensionType(
                "This is not an ExternalPubExtension".into(),
            )),
        }
    }

    /// Get a reference to this extension as [`ExternalSendersExtension`].
    /// Returns an [`ExtensionError::InvalidExtensionType`] error if called on
    /// an [`Extension`] that's not a [`ExternalSendersExtension`].
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
            #[cfg(feature = "extensions-draft-08")]
            Extension::AppDataDictionary(_) => ExtensionType::AppDataDictionary,
            Extension::LastResort(_) => ExtensionType::LastResort,
            Extension::Unknown(kind, _) => ExtensionType::Unknown(*kind),
        }
    }
}

macro_rules! impl_from_extensions_validator {
    ($validator:ty, $error:ty) => {
        impl From<Extensions<$validator>> for Extensions<AnyObject> {
            fn from(value: Extensions<$validator>) -> Self {
                Extensions {
                    unique: value.unique,
                    _object: PhantomData,
                }
            }
        }

        impl TryFrom<Extensions<AnyObject>> for Extensions<$validator> {
            type Error = $error;

            fn try_from(value: Extensions<AnyObject>) -> Result<Self, $error> {
                value
                    .unique
                    .iter()
                    .try_for_each(<$validator as ExtensionValidator>::validate_extension_type)?;

                Ok(Extensions {
                    unique: value.unique,
                    _object: PhantomData,
                })
            }
        }
    };
}

impl_from_extensions_validator!(GroupContext, ExtensionTypeNotValidInGroupContextError);
impl_from_extensions_validator!(LeafNode, ExtensionTypeNotValidInLeafNodeError);
impl_from_extensions_validator!(KeyPackage, ExtensionTypeNotValidInKeyPackageError);

#[cfg(any(feature = "test-utils", test))]
impl Extensions<AnyObject> {
    /// Coerces the extensions to an Extensions with the given validator. Unsafe.
    pub(crate) fn coerce<T: ExtensionValidator>(self) -> Extensions<T> {
        Extensions {
            unique: self.unique,
            _object: PhantomData,
        }
    }
}
#[cfg(test)]
mod test {
    use itertools::Itertools;
    use tls_codec::{Deserialize, Serialize, VLBytes};

    use crate::{ciphersuite::HpkePublicKey, extensions::*};

    #[test]
    fn add() {
        let mut extensions: Extensions<AnyObject> = Extensions::default();
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
    fn add_try_from() {
        // Create some extensions with different extension types and test that
        // duplicates are rejected. The extension content does not matter in this test.
        let ext_x = Extension::ApplicationId(ApplicationIdExtension::new(b"Test"));
        let ext_y = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::default());

        let tests = [
            (vec![], true),
            (vec![ext_x.clone()], true),
            (vec![ext_x.clone(), ext_x.clone()], false),
            (vec![ext_x.clone(), ext_x.clone(), ext_x.clone()], false),
            (vec![ext_y.clone()], true),
            (vec![ext_y.clone(), ext_y.clone()], false),
            (vec![ext_y.clone(), ext_y.clone(), ext_y.clone()], false),
            (vec![ext_x.clone(), ext_y.clone()], true),
            (vec![ext_y.clone(), ext_x.clone()], true),
            (vec![ext_x.clone(), ext_x.clone(), ext_y.clone()], false),
            (vec![ext_y.clone(), ext_y.clone(), ext_x.clone()], false),
            (vec![ext_x.clone(), ext_y.clone(), ext_y.clone()], false),
            (vec![ext_y.clone(), ext_x.clone(), ext_x.clone()], false),
            (vec![ext_x.clone(), ext_y.clone(), ext_x.clone()], false),
            (vec![ext_y.clone(), ext_x, ext_y], false),
        ];

        for (test, should_work) in tests.into_iter() {
            // Test `add`.
            {
                let mut extensions: Extensions<AnyObject> = Extensions::default();

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

            // Test `try_from`.
            if should_work {
                assert!(Extensions::<AnyObject>::try_from(test).is_ok());
            } else {
                assert!(Extensions::<AnyObject>::try_from(test).is_err());
            }
        }
    }

    #[test]
    fn ensure_ordering() {
        // Create some extensions with different extension types and test
        // that all permutations keep their order after being (de)serialized.
        // The extension content does not matter in this test.
        let ext_x = Extension::ApplicationId(ApplicationIdExtension::new(b"Test"));
        let ext_y = Extension::ExternalPub(ExternalPubExtension::new(HpkePublicKey::new(vec![])));
        let ext_z = Extension::RequiredCapabilities(RequiredCapabilitiesExtension::default());

        for candidate in [ext_x, ext_y, ext_z]
            .into_iter()
            .permutations(3)
            .collect::<Vec<_>>()
        {
            let candidate: Extensions<AnyObject> = Extensions::try_from(candidate).unwrap();
            let bytes = candidate.tls_serialize_detached().unwrap();
            let got = Extensions::tls_deserialize(&mut bytes.as_slice()).unwrap();
            assert_eq!(candidate, got);
        }
    }

    #[test]
    fn that_unknown_extensions_are_de_serialized_correctly() {
        let extension_types = [0x0000u16, 0x0A0A, 0x7A7A, 0xF100, 0xFFFF];
        let extension_datas = [vec![], vec![0], vec![1, 2, 3]];

        for extension_type in extension_types.into_iter() {
            for extension_data in extension_datas.iter() {
                // Construct an unknown extension manually.
                let test = {
                    let mut buf = extension_type.to_be_bytes().to_vec();
                    buf.append(
                        &mut VLBytes::new(extension_data.clone())
                            .tls_serialize_detached()
                            .unwrap(),
                    );
                    buf
                };

                // Test deserialization.
                let got = Extension::tls_deserialize_exact(&test).unwrap();

                match got {
                    Extension::Unknown(got_extension_type, ref got_extension_data) => {
                        assert_eq!(extension_type, got_extension_type);
                        assert_eq!(extension_data, &got_extension_data.0);
                    }
                    other => panic!("Expected `Extension::Unknown`, got {other:?}"),
                }

                // Test serialization.
                let got_serialized = got.tls_serialize_detached().unwrap();
                assert_eq!(test, got_serialized);
            }
        }
    }
}
