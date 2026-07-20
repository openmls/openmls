//! # Group Context

use openmls_traits::types::Ciphersuite;

use super::*;
use crate::versions::ProtocolVersion;

/// 8.1 Group Context
///
///```c
/// struct {
///     ProtocolVersion version = mls10;
///     CipherSuite cipher_suite;
///     opaque group_id<V>;
///     uint64 epoch;
///     opaque tree_hash<V>;
///     opaque confirmed_transcript_hash<V>;
///     Extension extensions<V>;
/// } GroupContext;
///
/// The [`GroupContext`] is a state object maintained which summarizes the group
/// state agreed upon by each member of the group.
///```
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct GroupContext {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    group_id: GroupId,
    epoch: GroupEpoch,
    tree_hash: VLBytes,
    confirmed_transcript_hash: VLBytes,
    extensions: Extensions,
}

impl GroupContext {
    /// Return the protocol version.
    pub fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Return the ciphersuite.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite
    }

    /// Return the group ID.
    pub fn group_id(&self) -> &GroupId {
        &self.group_id
    }

    /// Return the epoch.
    pub fn epoch(&self) -> GroupEpoch {
        self.epoch
    }
}
