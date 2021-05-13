use std::{any::Any, convert::TryFrom, fmt::Debug};

use crate::codec::{decode_vec, encode_vec, Codec, CodecError, Cursor, VecSize};
pub(crate) use serde::{Deserialize, Serialize};

mod capabilities_extension;
pub mod errors;
mod group_info_extension;
mod key_package_id_extension;
mod life_time_extension;
mod parent_hash_extension;
mod ratchet_tree_extension;

pub use capabilities_extension::CapabilitiesExtension;
pub use errors::*;
pub use group_info_extension::GroupInfoExtension;
pub use key_package_id_extension::KeyIdExtension;
pub use life_time_extension::LifetimeExtension;
pub(crate) use parent_hash_extension::ParentHashExtension;
pub use ratchet_tree_extension::RatchetTreeExtension;

#[cfg(test)]
mod test_extensions;

/// # Extension types
///
/// [IANA registrations](https://messaginglayersecurity.rocks/mls-protocol/draft-ietf-mls-protocol.html#name-mls-extension-types)
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub enum ExtensionType {
    Reserved,
    Capabilities,
    Lifetime,
    KeyId,
    ParentHash,
    RatchetTree,
    Custom(u16),
}

impl From<ExtensionType> for u16 {
    fn from(extension_type: ExtensionType) -> Self {
        match extension_type {
            ExtensionType::Reserved => 0,
            ExtensionType::Capabilities => 1,
            ExtensionType::Lifetime => 2,
            ExtensionType::KeyId => 3,
            ExtensionType::ParentHash => 4,
            ExtensionType::RatchetTree => 5,
            ExtensionType::Custom(value) => value,
        }
    }
}

/// The default extension type is invalid.
/// This has to be set explicitly.
impl Default for ExtensionType {
    fn default() -> Self {
        ExtensionType::Reserved
    }
}

impl TryFrom<u16> for ExtensionType {
    type Error = CodecError;

    /// Get the `ExtensionType` from a u16.
    /// Returns an error if the extension type is not known or not in the custom range.
    /// Note that this returns a [`CodecError`](`crate::codec::CodecError`).
    fn try_from(a: u16) -> Result<Self, Self::Error> {
        match a {
            0 => Ok(ExtensionType::Reserved),
            1 => Ok(ExtensionType::Capabilities),
            2 => Ok(ExtensionType::Lifetime),
            3 => Ok(ExtensionType::KeyId),
            4 => Ok(ExtensionType::ParentHash),
            5 => Ok(ExtensionType::RatchetTree),
            _ => {
                // Check that we are in the IANA range
                if a < 0xff00 {
                    return Err(CodecError::DecodingError);
                }
                Ok(ExtensionType::Custom(a))
            }
        }
    }
}

impl Codec for ExtensionType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(*self).encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = u16::decode(cursor)?;
        Self::try_from(value)
    }
}

/// # Extension struct
///
/// An extension has an `ExtensionType` and an opaque payload (byte vector).
/// This is only used for encoding and decoding.
///
/// See IANA registry for registered values
///
/// ```text
/// uint16 ExtensionType;
///
/// struct {
///     ExtensionType extension_type;
///     opaque extension_data<0..2^16-1>;
/// } Extension;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExtensionStruct {
    extension_type: ExtensionType,
    extension_data: Vec<u8>,
}

impl<'a> ExtensionStruct {
    /// Build a new `ExtensionStruct`.
    pub(crate) fn new(extension_type: ExtensionType, extension_data: Vec<u8>) -> Self {
        Self {
            extension_type,
            extension_data,
        }
    }

    /// Get the extension type
    pub fn extension_type(&self) -> ExtensionType {
        self.extension_type
    }

    /// Get the data of this extension struct.
    #[cfg(any(feature = "expose-test-vectors", test))]
    pub fn extension_data(&'a self) -> &'a [u8] {
        &self.extension_data
    }
}

impl Codec for ExtensionStruct {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.extension_type.encode(buffer)?;
        encode_vec(VecSize::VecU16, buffer, &self.extension_data)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let extension_type = ExtensionType::decode(cursor)?;
        let extension_data = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self {
            extension_type,
            extension_data,
        })
    }
}

/// Build a new extension of the given type from a byte slice.
fn from_bytes(ext_type: ExtensionType, bytes: &[u8]) -> Result<Box<dyn Extension>, ExtensionError> {
    match ext_type {
        ExtensionType::Capabilities => Ok(Box::new(CapabilitiesExtension::new_from_bytes(bytes)?)),
        ExtensionType::KeyId => Ok(Box::new(KeyIdExtension::new_from_bytes(bytes)?)),
        ExtensionType::Lifetime => Ok(Box::new(LifetimeExtension::new_from_bytes(bytes)?)),
        ExtensionType::ParentHash => Ok(Box::new(ParentHashExtension::new_from_bytes(bytes)?)),
        ExtensionType::RatchetTree => Ok(Box::new(RatchetTreeExtension::new_from_bytes(bytes)?)),
        _ => Err(ExtensionError::InvalidExtensionType(
            format!("Invalid extension type {:?}.", ext_type).into(),
        )),
    }
}

/// Encode extensions with TLS encoding. This is used whenever a struct contains
/// extensions.
pub(crate) fn encode_extensions(
    extensions: &[Box<dyn Extension>],
    buffer: &mut Vec<u8>,
) -> Result<(), CodecError> {
    let encoded_extensions: Vec<ExtensionStruct> =
        extensions.iter().map(|e| e.to_extension_struct()).collect();
    encode_vec(VecSize::VecU32, buffer, &encoded_extensions)?;
    Ok(())
}

/// Read a list of extensions from a `Cursor` into a vector of `Extension`s.
///
/// Note that this function returns a `CodecError` instead of an
/// `ExtensionError` because it's only used in decoding functions.
pub(crate) fn extensions_vec_from_cursor(
    cursor: &mut Cursor,
) -> Result<Vec<Box<dyn Extension>>, CodecError> {
    // First parse the extension bytes into the `ExtensionStruct`.
    let extension_struct_vec: Vec<ExtensionStruct> = decode_vec(VecSize::VecU32, cursor)?;

    // Now create the result vector of `Extension`s.
    let mut result: Vec<Box<dyn Extension>> = Vec::new();
    for extension in extension_struct_vec.iter() {
        // Make sure there are no duplicate extensions.
        if result
            .iter()
            .any(|e| e.extension_type() == extension.extension_type)
        {
            return Err(CodecError::DecodingError);
        }
        let ext = match from_bytes(extension.extension_type, &extension.extension_data) {
            Ok(r) => r,
            Err(_) => return Err(CodecError::DecodingError),
        };
        result.push(ext);
    }

    Ok(result)
}

/// # Extension
///
/// This trait defines functions to interact with an extension.
#[typetag::serde(tag = "type")]
pub trait Extension: Debug + ExtensionHelper + Send + Sync {
    /// Build a new extension from a byte slice.
    ///
    /// Note that all implementations of this trait are not public such that
    /// this function can't be used outside of the library.
    fn new_from_bytes(bytes: &[u8]) -> Result<Self, ExtensionError>
    where
        Self: Sized;

    /// Each extension has an extension type.
    /// This should be an associated constant really.
    /// See <https://github.com/rust-lang/rust/issues/46969> for reference.
    fn extension_type(&self) -> ExtensionType;

    /// Get the extension as `ExtensionStruct` for encoding.
    fn to_extension_struct(&self) -> ExtensionStruct;

    /// Get a generic trait object for downcasting.
    fn as_any(&self) -> &dyn Any;

    /// Get a reference to the `ParentHashExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `ParentHashExtension`.
    fn to_parent_hash_extension(&self) -> Result<&ParentHashExtension, ExtensionError> {
        match self.as_any().downcast_ref::<ParentHashExtension>() {
            Some(e) => Ok(e),
            None => Err(ExtensionError::InvalidExtensionType(
                "This is not a ParentHashExtension".into(),
            )),
        }
    }

    /// Get a reference to the `CapabilitiesExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `CapabilitiesExtension`.
    fn to_capabilities_extension(&self) -> Result<&CapabilitiesExtension, ExtensionError> {
        match self.as_any().downcast_ref::<CapabilitiesExtension>() {
            Some(e) => Ok(e),
            None => Err(ExtensionError::InvalidExtensionType(
                "This is not a CapabilitiesExtension".into(),
            )),
        }
    }

    /// Get a reference to the `LifetimeExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `LifetimeExtension`.
    fn to_lifetime_extension(&self) -> Result<&LifetimeExtension, ExtensionError> {
        match self.as_any().downcast_ref::<LifetimeExtension>() {
            Some(e) => Ok(e),
            None => Err(ExtensionError::InvalidExtensionType(
                "This is not a LifetimeExtension".into(),
            )),
        }
    }

    /// Get a reference to the `KeyIDExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `KeyIDExtension`.
    fn to_key_id_extension(&self) -> Result<&KeyIdExtension, ExtensionError> {
        match self.as_any().downcast_ref::<KeyIdExtension>() {
            Some(e) => Ok(e),
            None => Err(ExtensionError::InvalidExtensionType(
                "This is not a KeyIDExtension".into(),
            )),
        }
    }

    /// Get a reference to the `RatchetTreeExtension`.
    /// Returns an `InvalidExtensionType` error if called on an `Extension`
    /// that's not a `RatchetTreeExtension`.
    fn as_ratchet_tree_extension(&self) -> Result<&RatchetTreeExtension, ExtensionError> {
        match self.as_any().downcast_ref::<RatchetTreeExtension>() {
            Some(e) => Ok(e),
            None => Err(ExtensionError::InvalidExtensionType(
                "This is not a RatchetTreeExtension".into(),
            )),
        }
    }
}

// A slightly hacky work around to make `Extensions` clonable.
pub trait ExtensionHelper {
    fn clone_it(&self) -> Box<dyn Extension>;
}

impl<T> ExtensionHelper for T
where
    T: 'static + Extension + Clone + Default,
{
    fn clone_it(&self) -> Box<dyn Extension> {
        Box::new(self.clone())
    }
}

// Implement necessary traits (Clone, PartialEq) that we can't derive.

impl Clone for Box<dyn Extension> {
    fn clone(&self) -> Box<dyn Extension>
    where
        Self: Sized,
    {
        self.clone_it()
    }
}

impl PartialEq for dyn Extension {
    fn eq(&self, other: &Self) -> bool {
        if self.extension_type() != other.extension_type() {
            return false;
        }

        self.to_extension_struct() == other.to_extension_struct()
    }
}

impl Eq for dyn Extension {}

impl PartialOrd for dyn Extension {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.extension_type().partial_cmp(&other.extension_type())
    }
}

impl Ord for dyn Extension {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.extension_type().cmp(&other.extension_type())
    }
}
