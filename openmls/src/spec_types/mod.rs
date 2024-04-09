use serde::Serialize;
use tls_codec::{TlsSerialize, TlsSize, VLBytes};

// types
pub mod credential;
pub mod extensions;
pub mod framing;
pub mod hpke;
pub mod key_package;
pub mod keys;
pub mod proposals;
pub mod proprietary;
pub mod psk;
pub mod tree;

// impls
mod codec;
mod conversion;

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
#[derive(PartialEq, Eq, Copy, Clone, Debug, TlsSize, TlsSerialize)]
pub struct Lifetime {
    not_before: u64,
    not_after: u64,
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
//#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, TlsSize, TlsSerialize)]
//#[repr(u16)]
//#[allow(missing_docs)]
//pub enum ProtocolVersion {
//Mls10 = 1,
//Mls10Draft11 = 200,
//}
pub use openmls_spec_types::ProtocolVersion;

//impl From<ProtocolVersion> for openmls_spec_types::ProtocolVersion {
//    fn from(value: ProtocolVersion) -> Self {
//        match value {
//            ProtocolVersion::Mls10 => openmls_spec_types::ProtocolVersion::Mls10,
//            ProtocolVersion::Mls10Draft11 => openmls_spec_types::ProtocolVersion::Mls10Draft11,
//        }
//    }
//}
//
///// There's only one version right now, which is the default.
//impl Default for ProtocolVersion {
//    fn default() -> Self {
//        ProtocolVersion::Mls10
//    }
//}

/// A ciphersuite ID.
///
/// Used to accept any value, e.g., in `Capabilities`.
// #[derive(Clone, Copy, Debug, PartialEq, Eq, TlsSize, TlsSerialize)]
//pub struct Ciphersuite(pub(super) u16);
pub use openmls_spec_types::Ciphersuite;

#[derive(Debug, PartialEq, Eq, Clone, TlsSize, TlsSerialize, Serialize)]
pub struct Signature {
    value: VLBytes,
}

impl From<Vec<u8>> for Signature {
    fn from(value: Vec<u8>) -> Self {
        Self {
            value: value.into(),
        }
    }
}

#[cfg(test)]
impl Signature {
    pub(crate) fn modify(&mut self, value: &[u8]) {
        self.value = value.to_vec().into();
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl Signature {
    /// Get this signature as slice.
    pub(super) fn value(&self) -> &[u8] {
        self.value.as_slice()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, TlsSize, TlsSerialize)]
pub struct GroupEpoch(u64);

/// A group ID. The group ID is chosen by the creator of the group and should be globally unique.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, TlsSize, TlsSerialize)]
pub struct GroupId {
    value: VLBytes,
}

/// A reference to an MLS object computed as a hash of the value.
#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, TlsSize, TlsSerialize)]
pub struct HashReference {
    value: VLBytes,
}
