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
//!
use super::{Extension, ExtensionType};
use crate::codec::{Codec, Cursor};

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(PartialEq, Clone, Debug)]
pub struct LifetimeExtension {
    not_before: u64,
    not_after: u64,
}

impl LifetimeExtension {
    pub const LIFETIME_1_MINUTE: u64 = 60;
    pub const LIFETIME_1_HOUR: u64 = 60 * LifetimeExtension::LIFETIME_1_MINUTE;
    pub const LIFETIME_1_DAY: u64 = 24 * LifetimeExtension::LIFETIME_1_HOUR;
    pub const LIFETIME_1_WEEK: u64 = 7 * LifetimeExtension::LIFETIME_1_DAY;
    pub const LIFETIME_4_WEEKS: u64 = 4 * LifetimeExtension::LIFETIME_1_WEEK;
    pub const LIFETIME_MARGIN: u64 = LifetimeExtension::LIFETIME_1_HOUR;
    pub fn new(t: u64) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let not_before = now - LifetimeExtension::LIFETIME_MARGIN;
        let not_after = now + t + LifetimeExtension::LIFETIME_MARGIN;
        Self {
            not_before,
            not_after,
        }
    }
    pub fn new_from_bytes(bytes: &[u8]) -> Self {
        let mut cursor = Cursor::new(bytes);
        let not_before = u64::decode(&mut cursor).unwrap();
        let not_after = u64::decode(&mut cursor).unwrap();
        Self {
            not_before,
            not_after,
        }
    }
    pub fn to_extension(&self) -> Extension {
        let mut extension_data: Vec<u8> = vec![];
        self.not_before.encode(&mut extension_data).unwrap();
        self.not_after.encode(&mut extension_data).unwrap();
        let extension_type = ExtensionType::Lifetime;
        Extension {
            extension_type,
            extension_data,
        }
    }
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.not_before < now && self.not_after > now
    }
}
