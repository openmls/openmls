use serde::{Deserialize, Serialize};

pub mod credential;
pub mod extensions;
pub mod hpke;
pub mod key_package;
pub mod keys;
pub mod proposals;
pub mod psk;
pub mod tree;

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
#[derive(PartialEq, Eq, Copy, Clone, Debug, Serialize, Deserialize)]
pub struct Lifetime {
    pub not_before: u64,
    pub not_after: u64,
}

/// # Protocol Version
///
/// ```text
/// enum {
///     reserved(0),
///     mls10(1),
///     (65535)
/// } ProtocolVersion;
/// ```
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u16)]
#[allow(missing_docs)]
pub enum ProtocolVersion {
    Mls10 = 1,
    Mls10Draft11 = 200,
}

/// A ciphersuite ID.
///
/// Used to accept any value, e.g., in `Capabilities`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphersuite(pub u16);

#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub value: VLBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct GroupEpoch(pub u64);

/// A group ID. The group ID is chosen by the creator of the group and should be globally unique.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize, Serialize)]
pub struct GroupId {
    pub value: VLBytes,
}

/// A reference to an MLS object computed as a hash of the value.
#[derive(Clone, Debug, Hash, PartialEq, Eq, Serialize, Ord, PartialOrd, Deserialize)]
pub struct HashReference {
    pub value: VLBytes,
}

pub type VLBytes = Vec<u8>;
