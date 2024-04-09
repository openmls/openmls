use super::extensions::{ExtensionType, Extensions};
use super::keys::InitKey;
use super::tree::LeafNode;
use super::{Ciphersuite, Signature};
use super::{HashReference, ProtocolVersion};

use crate::ciphersuite::hash_ref::make_key_package_ref;
use crate::error::LibraryError;

use openmls_traits::crypto::OpenMlsCrypto;
use serde::Serialize;
use tls_codec::{Serialize as _, TlsSerialize, TlsSize};

/// The key package struct.
#[derive(Debug, Clone, TlsSize, TlsSerialize, Serialize)]
pub struct KeyPackage {
    pub(super) payload: KeyPackageTbs,
    pub(super) signature: Signature,
}

impl KeyPackage {
    /// Get a reference to the extensions of this key package.
    pub fn extensions(&self) -> &Extensions {
        &self.payload.extensions
    }
    ///
    /// Compute the [`KeyPackageRef`] of this [`KeyPackage`].
    /// The [`KeyPackageRef`] is used to identify a new member that should get
    /// added to a group.
    pub fn hash_ref(&self, crypto: &impl OpenMlsCrypto) -> Result<KeyPackageRef, LibraryError> {
        make_key_package_ref(
            &self
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
            self.payload.ciphersuite,
            crypto,
        )
        .map_err(LibraryError::unexpected_crypto_error)
    }

    /// Get the [`Ciphersuite`].
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.payload.ciphersuite
    }

    /// Get the [`LeafNode`] reference.
    pub fn leaf_node(&self) -> &LeafNode {
        &self.payload.leaf_node
    }

    /// Get the public HPKE init key of this key package.
    pub fn hpke_init_key(&self) -> &InitKey {
        &self.payload.init_key
    }

    /// Check if this KeyPackage is a last resort key package.
    pub fn last_resort(&self) -> bool {
        self.payload.extensions.contains(ExtensionType::LastResort)
    }

    /// Get the `ProtocolVersion`.
    pub(crate) fn protocol_version(&self) -> ProtocolVersion {
        self.payload.protocol_version
    }
}

impl PartialEq for KeyPackage {
    fn eq(&self, other: &Self) -> bool {
        // We ignore the signature in the comparison. The same key package
        // may have different, valid signatures.
        self.payload == other.payload
    }
}

impl crate::ciphersuite::signable::SignedStruct<KeyPackageTbs> for KeyPackage {
    fn from_payload(
        payload: KeyPackageTbs,
        signature: crate::ciphersuite::signature::Signature,
    ) -> Self {
        Self { payload, signature }
    }
}

impl From<KeyPackage> for KeyPackageTbs {
    fn from(kp: KeyPackage) -> Self {
        kp.payload
    }
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

// impl MlsEntity for KeyPackage {
//   const ID: MlsEntityId = MlsEntityId::KeyPackage;
//}
