//! Incoming KeyPackages. This modules contains deserialization and validation
//! of KeyPackages.

use crate::{
    ciphersuite::*, extensions::Extensions, treesync::node::leaf_node::LeafNodeIn,
    versions::ProtocolVersion,
};
use openmls_traits::types::Ciphersuite;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::InitKey;

/// The unsigned payload of a key package.
///
/// ```text
/// struct {
///     ProtocolVersion version;
///     CipherSuite cipher_suite;
///     HPKEPublicKey init_key;
///     LeafNode leaf_node;
///     Extension extensions<V>;
/// } KeyPackageTBS;
/// ```
#[derive(
    Debug,
    Clone,
    PartialEq,
    TlsSize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    Serialize,
    Deserialize,
)]
struct KeyPackageTbsIn {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    init_key: InitKey,
    leaf_node: LeafNodeIn,
    extensions: Extensions,
}

/// The key package struct.
#[derive(
    Debug,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct KeyPackageIn {
    payload: KeyPackageTbsIn,
    signature: Signature,
}

impl KeyPackageIn {
    /// Returns true if the protocol version is supported by this key package and
    /// false otherwise.
    pub(crate) fn version_is_supported(&self, protocol_version: ProtocolVersion) -> bool {
        self.payload.protocol_version == protocol_version
    }
}
