//! # Key Packages
//!
//! Key packages are pre-published public keys that carry information about a
//! user, allowing for the asynchronous addition of clients to an MLS group.
//!
//! A key package object specifies:
//!
//! - A **protocol version** and ciphersuite that the client supports
//! - A **public key** that others can use for key agreement
//! - A **credential** authenticating the client's application-layer identity
//! - A list of **extensions** for the key package (see
//!   [Extensions](`mod@crate::extensions`) for details)
//!
//! Key packages are meant to be used only once and SHOULD NOT be reused,
//! except as a last resort—i.e., when no other key package is available.
//! Clients MAY generate and publish multiple key packages to support multiple
//! ciphersuites.

use crate::{
    ciphersuite::{hash_ref::KeyPackageRef, *},
    error::LibraryError,
    extensions::Extensions,
    treesync::{node::encryption_keys::EncryptionPrivateKey, LeafNode},
    versions::ProtocolVersion,
};
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
};

// Private

// Public
pub mod errors;
pub mod key_package_in;

mod lifetime;

// Public types
pub use key_package_in::KeyPackageIn;
pub use lifetime::Lifetime;

/// The unsigned payload of a key package.
/// Any modification must happen on this unsigned struct. Use `sign` to get a
/// signed key package.
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
#[derive(Debug, Clone, PartialEq, TlsSize, TlsSerialize, Serialize, Deserialize)]
struct KeyPackageTbs {
    protocol_version: ProtocolVersion,
    ciphersuite: Ciphersuite,
    init_key: InitKey,
    leaf_node: LeafNode,
    extensions: Extensions,
}

/// The key package struct.
#[derive(Debug, Clone, Serialize, Deserialize, TlsSize, TlsSerialize)]
pub struct KeyPackage {
    payload: KeyPackageTbs,
    signature: Signature,
}

impl PartialEq for KeyPackage {
    fn eq(&self, other: &Self) -> bool {
        // We ignore the signature in the comparison. The same key package
        // may have different, valid signatures.
        self.payload == other.payload
    }
}

/// Init key for HPKE.
#[derive(
    Debug,
    Clone,
    PartialEq,
    TlsSize,
    TlsSerialize,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsDeserializeBytes,
)]
pub struct InitKey {
    key: HpkePublicKey,
}

/// A [`KeyPackageBundle`] contains a [`KeyPackage`] and the init and encryption
/// private key.
///
/// This is stored to ensure the private key is handled together with the key
/// package.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackageBundle {
    pub(crate) key_package: KeyPackage,
    pub(crate) private_init_key: HpkePrivateKey,
    pub(crate) private_encryption_key: EncryptionPrivateKey,
}
