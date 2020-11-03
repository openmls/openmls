//! # KeyPackage Identifiers
//!
//! > Key Package Extension
//!
//! 7.3. KeyPackage Identifiers
//!
//! Within MLS, a KeyPackage is identified by its hash (see, e.g., Section 11.2.1).
//! The key_id extension allows applications to add an explicit,
//! application-defined identifier to a KeyPackage.
//!
//! ```text
//! opaque key_id<0..2^16-1>;
//! ```
//!

use super::{Extension, ExtensionStruct, ExtensionType};
use crate::codec::{decode_vec, encode_vec, Cursor, VecSize};
use crate::errors::ConfigError;

#[derive(PartialEq, Clone, Debug, Default)]
pub struct KeyIDExtension {
    key_id: Vec<u8>,
}

impl KeyIDExtension {
    /// Create a new key identifier extension from a byte slice.
    pub fn new(id: &[u8]) -> Self {
        Self {
            key_id: id.to_vec(),
        }
    }

    /// Get the value of the key id as byte slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.key_id
    }
}

impl Extension for KeyIDExtension {
    fn get_type(&self) -> ExtensionType {
        ExtensionType::KeyID
    }

    /// Build a new KeyIDExtension from a byte slice.
    fn new_from_bytes(bytes: &[u8]) -> Result<Self, ConfigError>
    where
        Self: Sized,
    {
        let cursor = &mut Cursor::new(bytes);
        let key_id = decode_vec(VecSize::VecU16, cursor).unwrap();
        Ok(Self { key_id })
    }

    fn to_extension_struct(&self) -> ExtensionStruct {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU16, &mut extension_data, &self.key_id).unwrap();
        let extension_type = ExtensionType::KeyID;
        ExtensionStruct::new(extension_type, extension_data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
