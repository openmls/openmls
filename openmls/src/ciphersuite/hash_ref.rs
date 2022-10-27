//! # Hash References
//!
//!
//! Some MLS messages refer to other MLS objects by hash.  For example, Welcome
//! messages refer to KeyPackages for the members being welcomed, and Commits refer
//! to Proposals they cover.  These identifiers are computed as follows:
//!
//! ```text
//! opaque HashReference<V>;
//!
//! MakeKeyPackageRef(value) = RefHash("MLS 1.0 KeyPackage Reference", value)
//! MakeProposalRef(value)   = RefHash("MLS 1.0 Proposal Reference", value)
//!
//! RefHash(label, value) = Hash(RefHashInput)
//!
//! Where RefHashInput is defined as:
//!
//! struct {
//!  opaque label<V> = label;
//!  opaque value<V> = value;
//! } RefHashInput;
//! ```
//!
//! For a KeyPackageRef, the `value` input is the encoded KeyPackage, and the
//! ciphersuite specified in the KeyPackage determines the hash function used.  For a
//! ProposalRef, the `value` input is the MLSPlaintext carrying the proposal, and
//! the hash function is determined by the group's ciphersuite.

use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Serialize as TlsSerializeTrait, TlsDeserialize, TlsSerialize, TlsSize, TlsSliceU8, VLBytes,
};

use super::Ciphersuite;

const KEY_PACKAGE_REF_LABEL: &[u8; 22] = b"MLS 1.0 KeyPackage ref";
const PROPOSAL_REF_LABEL: &[u8; 20] = b"MLS 1.0 Proposal ref";

/// A reference to an MLS object computed as a hash of the value.
#[derive(
    Clone,
    Hash,
    PartialEq,
    Eq,
    Serialize,
    Ord,
    PartialOrd,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct HashReference {
    value: VLBytes,
}

/// A reference to a key package.
/// This value uniquely identifies a key package.
pub type KeyPackageRef = HashReference;

/// A reference to a proposal.
/// This value uniquely identifies a proposal.
pub type ProposalRef = HashReference;

#[derive(TlsSerialize, TlsSize)]
struct HashReferenceInput<'a> {
    label: TlsSliceU8<'a, u8>,
    value: VLBytes,
}

/// Compute a new [`ProposalRef`] value for a `value`.
pub fn make_proposal_ref(
    value: &[u8],
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCrypto,
) -> Result<ProposalRef, CryptoError> {
    HashReference::new(value, ciphersuite, backend, PROPOSAL_REF_LABEL)
}

/// Compute a new [`KeyPackageRef`] value for a `value`.
pub fn make_key_package_ref(
    value: &[u8],
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCrypto,
) -> Result<KeyPackageRef, CryptoError> {
    HashReference::new(value, ciphersuite, backend, KEY_PACKAGE_REF_LABEL)
}

impl HashReference {
    /// Compute a new [`HashReference`] value for a `value`.
    pub fn new(
        value: &[u8],
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCrypto,
        label: &[u8],
    ) -> Result<Self, CryptoError> {
        let input = HashReferenceInput {
            label: TlsSliceU8(label),
            value: VLBytes::new(value.to_vec()),
        };
        let payload = input
            .tls_serialize_detached()
            .map_err(|_| CryptoError::TlsSerializationError)?;
        let value = backend.hash(ciphersuite.hash_algorithm(), &payload)?;
        Ok(Self {
            value: VLBytes::new(value),
        })
    }

    /// Get a reference to the hash reference's value as slice.
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            value: VLBytes::from(slice),
        }
    }
}

impl core::fmt::Display for HashReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HashReference: ")?;
        for b in self.value.as_slice() {
            write!(f, "{:02X}", b)?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for HashReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
