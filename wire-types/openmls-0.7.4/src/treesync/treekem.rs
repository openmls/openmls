//! Module to encrypt and decrypt update paths for a [`TreeSyncDiff`] instance.
//!
//! # About
//!
//! This module contains structs and functions to encrypt and decrypt path
//! updates for a [`TreeSyncDiff`] instance.

use openmls_traits::types::HpkeCiphertext;
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use super::{
    node::{encryption_keys::EncryptionKey, leaf_node::LeafNodeIn},
    LeafNode,
};

/// 8.6. Update Paths
///
/// ```text
/// struct {
///     HPKEPublicKey public_key;
///     HPKECiphertext encrypted_path_secret<V>;
/// } UpdatePathNode;
/// ```
#[derive(
    Debug,
    Eq,
    PartialEq,
    Clone,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct UpdatePathNode {
    pub(super) public_key: EncryptionKey,
    pub(super) encrypted_path_secrets: Vec<HpkeCiphertext>,
}

/// 8.6. Update Paths
///
/// ```text
/// struct {
///     LeafNode leaf_node;
///     UpdatePathNode nodes<V>;
/// } UpdatePath;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Serialize, Deserialize, TlsSerialize, TlsSize)]
pub struct UpdatePath {
    leaf_node: LeafNode,
    nodes: Vec<UpdatePathNode>,
}

#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Serialize,
    Deserialize,
    TlsSerialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSize,
)]
pub struct UpdatePathIn {
    leaf_node: LeafNodeIn,
    nodes: Vec<UpdatePathNode>,
}
