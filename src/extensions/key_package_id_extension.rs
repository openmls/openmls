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

use super::{Extension, ExtensionType};
use crate::codec::{decode_vec, encode_vec, Cursor, VecSize};

#[derive(PartialEq, Clone, Debug)]
pub struct KeyIDExtension {
    key_id: Vec<u8>,
}

impl KeyIDExtension {
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let cursor = &mut Cursor::new(bytes);
        let key_id = decode_vec(VecSize::VecU16, cursor).unwrap();
        Self { key_id }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        encode_vec(VecSize::VecU16, &mut extension_data, &self.key_id).unwrap();
        let extension_type = ExtensionType::KeyID;
        Extension {
            extension_type,
            extension_data,
        }
    }
}
