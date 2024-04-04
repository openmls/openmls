use super::extensions::Extensions;
use super::keys::InitKey;
use super::tree::LeafNode;
use super::{Ciphersuite, Signature};
use super::{HashReference, ProtocolVersion};

/// The key package struct.
#[derive(Debug, Clone, PartialEq)]
pub struct KeyPackage {
    pub(super) payload: KeyPackageTbs,
    pub(super) signature: Signature,
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
#[derive(Clone, Debug, PartialEq)]
pub struct KeyPackageTbs {
    pub(super) protocol_version: ProtocolVersion,
    pub(super) ciphersuite: Ciphersuite,
    pub(super) init_key: InitKey,
    pub(super) leaf_node: LeafNode,
    pub(super) extensions: Extensions,
}

/// A reference to a key package.
/// This value uniquely identifies a key package.
#[derive(Clone, Debug, PartialEq)]
pub struct KeyPackageRef(pub(super) HashReference);
