//! # Life time extension
//!
//! > KeyPackage Extension
//!
//! 7.2. Lifetime
//!
//! The lifetime extension represents the times between which clients will
//! consider a KeyPackage valid. This time is represented as an absolute time,
//! measured in seconds since the Unix epoch (1970-01-01T00:00:00Z).
//! A client MUST NOT use the data in a KeyPackage for any processing before
//! the not_before date, or after the not_after date.
//!
//! Applications MUST define a maximum total lifetime that is acceptable for a
//! KeyPackage, and reject any KeyPackage where the total lifetime is longer
//! than this duration.This extension MUST always be present in a KeyPackage.
//!
//! ``` text
//! uint64 not_before;
//! uint64 not_after;
//! ```
use super::{
    Deserialize, Extension, ExtensionError, ExtensionStruct, ExtensionType, LifetimeExtensionError,
    Serialize,
};
use crate::codec::{Codec, Cursor};
use crate::config::Config;

use std::time::{SystemTime, UNIX_EPOCH};

/// The lifetime extension holds a not before and a not after time measured in
/// seconds since the Unix epoch (1970-01-01T00:00:00Z).
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct LifetimeExtension {
    not_before: u64,
    not_after: u64,
}

impl LifetimeExtension {
    /// Create a new lifetime extensions with lifetime `t` (in seconds).
    /// Note that the lifetime is extended 1h into the past to adapt to skewed
    /// clocks.
    pub fn new(t: u64) -> Self {
        let lifetime_margin: u64 = Config::key_package_lifetime_margin();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!")
            .as_secs();
        let not_before = now - lifetime_margin;
        let not_after = now + t;
        Self {
            not_before,
            not_after,
        }
    }

    /// Returns true if this lifetime is valid.
    pub(crate) fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("SystemTime before UNIX EPOCH!")
            .as_secs();
        self.not_before < now && now < self.not_after
    }
}

impl Default for LifetimeExtension {
    fn default() -> Self {
        LifetimeExtension::new(Config::default_key_package_lifetime())
    }
}

#[typetag::serde]
impl Extension for LifetimeExtension {
    fn extension_type(&self) -> ExtensionType {
        ExtensionType::Lifetime
    }

    /// Build a new LifetimeExtension from a byte slice.
    fn new_from_bytes(bytes: &[u8]) -> Result<Self, ExtensionError>
    where
        Self: Sized,
    {
        let mut cursor = Cursor::new(bytes);
        let not_before = u64::decode(&mut cursor)?;
        let not_after = u64::decode(&mut cursor)?;
        let out = Self {
            not_before,
            not_after,
        };
        if !out.is_valid() {
            return Err(ExtensionError::Lifetime(LifetimeExtensionError::Invalid));
        }
        Ok(out)
    }

    fn to_extension_struct(&self) -> ExtensionStruct {
        let mut extension_data: Vec<u8> = vec![];
        self.not_before.encode(&mut extension_data).unwrap();
        self.not_after.encode(&mut extension_data).unwrap();
        let extension_type = ExtensionType::Lifetime;
        ExtensionStruct::new(extension_type, extension_data)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
