#[cfg(target_arch = "wasm32")]
use fluvio_wasm_timer::{SystemTime, UNIX_EPOCH};
#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

/// This value is used as the default lifetime if no default  lifetime is configured.
/// The value is in seconds and amounts to 3 * 28 Days, i.e. about 3 months.
const DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS: u64 = 60 * 60 * 24 * 28 * 3;

/// This value is used as the default amount of time (in seconds) the lifetime
/// of a `KeyPackage` is extended into the past to allow for skewed clocks. The
/// value is in seconds and amounts to 1h.
const DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS: u64 = 60 * 60;

/// The maximum total lifetime range that is acceptable for a leaf node.
/// The value is in seconds and amounts to 3 * 28 Days, i.e., about 3 months.
const MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS: u64 =
    DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS + DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS;

/// The lifetime represents the times between which clients will
/// consider a KeyPackage valid. This time is represented as an absolute time,
/// measured in seconds since the Unix epoch (1970-01-01T00:00:00Z).
/// A client MUST NOT use the data in a KeyPackage for any processing before
/// the not_before date, or after the not_after date.
///
/// Applications MUST define a maximum total lifetime that is acceptable for a
/// KeyPackage, and reject any KeyPackage where the total lifetime is longer
/// than this duration.This extension MUST always be present in a KeyPackage.
///
/// ```c
/// // draft-ietf-mls-protocol-16
/// struct {
///     uint64 not_before;
///     uint64 not_after;
/// } Lifetime;
/// ```
#[derive(
    PartialEq,
    Eq,
    Copy,
    Clone,
    Debug,
    TlsSerialize,
    TlsSize,
    TlsDeserialize,
    TlsDeserializeBytes,
    Serialize,
    Deserialize,
)]
pub struct Lifetime {
    not_before: u64,
    not_after: u64,
}

impl Lifetime {
    /// Returns true if this lifetime is valid.
    pub fn is_valid(&self) -> bool {
        match SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
        {
            Ok(elapsed) => self.not_before < elapsed && elapsed < self.not_after,
            Err(_) => {
                log::error!("SystemTime before UNIX EPOCH.");
                false
            }
        }
    }

    /// ValSem(openmls/annotations#32):
    /// Applications MUST define a maximum total lifetime that is acceptable for a LeafNode,
    /// and reject any LeafNode where the total lifetime is longer than this duration.
    pub fn has_acceptable_range(&self) -> bool {
        self.not_after.saturating_sub(self.not_before) <= MAX_LEAF_NODE_LIFETIME_RANGE_SECONDS
    }

    /// Returns the "not before" timestamp of the KeyPackage.
    pub fn not_before(&self) -> u64 {
        self.not_before
    }

    /// Returns the "not after" timestamp of the KeyPackage.
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
}
