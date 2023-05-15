use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

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
    PartialEq, Eq, Copy, Clone, Debug, TlsSerialize, TlsSize, TlsDeserialize, Serialize, Deserialize,
)]
pub struct Lifetime {
    not_before: u64,
    not_after: u64,
}

impl Lifetime {
    /// Create a new lifetime with lifetime `t` (in seconds).
    /// Note that the lifetime is extended 1h into the past to adapt to skewed
    /// clocks, i.e. `not_before` is set to now - 1h.
    pub fn new(t: u64) -> Self {
        let lifetime_margin: u64 = DEFAULT_KEY_PACKAGE_LIFETIME_MARGIN_SECONDS;
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
}

impl Default for Lifetime {
    fn default() -> Self {
        Lifetime::new(DEFAULT_KEY_PACKAGE_LIFETIME_SECONDS)
    }
}

#[cfg(test)]
mod tests {
    use tls_codec::{Deserialize, Serialize};

    use super::Lifetime;

    #[test]
    fn lifetime() {
        // A freshly created extensions must be valid.
        let ext = Lifetime::default();
        assert!(ext.is_valid());

        // An extension without lifetime is invalid (waiting for 1 second).
        let ext = Lifetime::new(0);
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(!ext.is_valid());

        // Test (de)serializing invalid extension
        let serialized = ext
            .tls_serialize_detached()
            .expect("error encoding life time extension");
        let ext_deserialized = Lifetime::tls_deserialize(&mut serialized.as_slice())
            .expect("Error deserializing lifetime");
        assert!(!ext_deserialized.is_valid());
    }
}
