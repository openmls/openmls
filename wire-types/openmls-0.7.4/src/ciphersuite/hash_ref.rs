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
//! ProposalRef, the `value` input is the PublicMessage carrying the proposal, and
//! the hash function is determined by the group's ciphersuite.

use openmls_traits::{crypto::OpenMlsCrypto, types::CryptoError};
use serde::{Deserialize, Serialize};
use tls_codec::{
    Serialize as TlsSerializeTrait, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize,
    VLByteSlice, VLBytes,
};

use super::Ciphersuite;

const KEY_PACKAGE_REF_LABEL: &[u8; 28] = b"MLS 1.0 KeyPackage Reference";
const PROPOSAL_REF_LABEL: &[u8; 26] = b"MLS 1.0 Proposal Reference";

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
    TlsDeserializeBytes,
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
    label: VLByteSlice<'a>,
    value: VLBytes,
}

impl core::fmt::Display for HashReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HashReference: ")?;
        for b in self.value.as_slice() {
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}

impl core::fmt::Debug for HashReference {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}
