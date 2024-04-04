use crate::extensions::Extensions;
use crate::keys::InitKey;
use crate::tree::LeafNode;
use crate::{Ciphersuite, Signature};
use crate::{HashReference, ProtocolVersion};

use serde::{Deserialize, Serialize};

/// The key package struct.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct KeyPackage {
    pub payload: KeyPackageTbs,
    pub signature: Signature,
}

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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPackageTbs {
    pub protocol_version: ProtocolVersion,
    pub ciphersuite: Ciphersuite,
    pub init_key: InitKey,
    pub leaf_node: LeafNode,
    pub extensions: Extensions,
}

/// A reference to a key package.
/// This value uniquely identifies a key package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPackageRef(pub HashReference);
