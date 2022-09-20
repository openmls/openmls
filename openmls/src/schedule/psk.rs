//! # Pre shared keys.
//! ```text
//! enum {
//!     reserved(0),
//!     external(1),
//!     reinit(2),
//!     branch(3),
//!     (255)
//!   } PSKType;
//!
//!   struct {
//!     PSKType psktype;
//!     select (PreSharedKeyID.psktype) {
//!       case external:
//!         opaque psk_id<0..255>;
//!
//!       case reinit:
//!         opaque psk_group_id<0..255>;
//!         uint64 psk_epoch;
//!
//!       case branch:
//!         opaque psk_group_id<0..255>;
//!         uint64 psk_epoch;
//!     }
//!     opaque psk_nonce<0..255>;
//!   } PreSharedKeyID;
//!
//!   struct {
//!       PreSharedKeyID psks<0..2^16-1>;
//!   } PreSharedKeys;
//! ```

use super::*;
use crate::group::{GroupEpoch, GroupId};
use openmls_traits::{key_store::OpenMlsKeyStore, random::OpenMlsRand, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use tls_codec::{Serialize as TlsSerializeTrait, TlsByteVecU8, TlsVecU16};

/// Type of PSK.
/// ```text
/// enum {
///   reserved(0),
///   external(1),
///   reinit(2),
///   branch(3),
///   (255)
/// } PSKType;
/// ```
#[derive(
    Debug,
    PartialEq,
    Eq,
    Clone,
    Copy,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
#[repr(u8)]
#[allow(missing_docs)]
pub enum PskType {
    External = 1,
    Reinit = 2,
    Branch = 3,
}

impl TryFrom<u8> for PskType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PskType::External),
            2 => Ok(PskType::Reinit),
            3 => Ok(PskType::Branch),
            _ => Err("Unknown PSK type."),
        }
    }
}

impl From<&Psk> for PskType {
    fn from(psk: &Psk) -> Self {
        match psk {
            Psk::External(_) => PskType::External,
            Psk::Reinit(_) => PskType::Reinit,
            Psk::Branch(_) => PskType::Branch,
        }
    }
}

/// External PSK.
#[derive(
    Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ExternalPsk {
    psk_id: TlsByteVecU8,
}

impl ExternalPsk {
    /// Create a new `ExternalPsk` from a PSK ID
    pub fn new(psk_id: Vec<u8>) -> Self {
        Self {
            psk_id: psk_id.into(),
        }
    }
    /// Return the PSK ID
    pub fn psk_id(&self) -> &[u8] {
        self.psk_id.as_slice()
    }
}

/// Contains the secret part of the PSK as well as the
/// public part that is used as a marker for injection into the key schedule.
#[derive(Serialize, Deserialize)]
pub(crate) struct PskBundle {
    secret: Secret,
}

impl PskBundle {
    /// Create a new bundle
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn new(secret: Secret) -> Result<Self, CryptoError> {
        Ok(Self { secret })
    }

    /// Return the secret
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }
}
/// ReInit PSK.
#[derive(
    Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct ReinitPsk {
    pub(crate) psk_group_id: GroupId,
    pub(crate) psk_epoch: GroupEpoch,
}

impl ReinitPsk {
    /// Return the `GroupId`
    pub fn psk_group_id(&self) -> &GroupId {
        &self.psk_group_id
    }
    /// Return the `GroupEpoch`
    pub fn psk_epoch(&self) -> GroupEpoch {
        self.psk_epoch
    }
}

/// Branch PSK
#[derive(
    Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize,
)]
pub struct BranchPsk {
    pub(crate) psk_group_id: GroupId,
    pub(crate) psk_epoch: GroupEpoch,
}

impl BranchPsk {
    /// Return the `GroupId`
    pub fn psk_group_id(&self) -> &GroupId {
        &self.psk_group_id
    }
    /// Return the `GroupEpoch`
    pub fn psk_epoch(&self) -> GroupEpoch {
        self.psk_epoch
    }
}

/// PSK enum that can contain the different PSK types
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
#[allow(missing_docs)]
pub enum Psk {
    External(ExternalPsk),
    Reinit(ReinitPsk),
    Branch(BranchPsk),
}

/// A `PreSharedKeyID` is used to uniquely identify the PSKs that get injected
/// in the key schedule.
/// ```text
/// struct {
///   PSKType psktype;
///   select (PreSharedKeyID.psktype) {
///     case external:
///       opaque psk_id<0..255>;
///
///     case reinit:
///       opaque psk_group_id<0..255>;
///       uint64 psk_epoch;
///
///     case branch:
///       opaque psk_group_id<0..255>;
///       uint64 psk_epoch;
///   }
///   opaque psk_nonce<0..255>;
/// } PreSharedKeyID;
/// ```
#[derive(Debug, PartialEq, Eq, Clone, Hash, Serialize, Deserialize)]
pub struct PreSharedKeyId {
    pub(crate) psk_type: PskType,
    pub(crate) psk: Psk,
    pub(crate) psk_nonce: TlsByteVecU8,
}

impl PreSharedKeyId {
    /// Create a new `PreSharedKeyID`
    pub fn new(
        ciphersuite: Ciphersuite,
        rand: &impl OpenMlsRand,
        psk: Psk,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            psk_type: PskType::from(&psk),
            psk,
            psk_nonce: rand
                .random_vec(ciphersuite.hash_length())
                .map_err(|_| CryptoError::InsufficientRandomness)?
                .into(),
        })
    }
    /// Return the type of the PSK
    pub fn psktype(&self) -> &PskType {
        &self.psk_type
    }
    /// Return the PSK
    pub fn psk(&self) -> &Psk {
        &self.psk
    }
    /// Return the PSK nonce
    pub fn psk_nonce(&self) -> &[u8] {
        self.psk_nonce.as_slice()
    }
}

/// `PreSharedKeys` is a vector of `PreSharedKeyID`s.
/// struct {
///     PreSharedKeyID psks<0..2^16-1>;
/// } PreSharedKeys;
#[derive(TlsDeserialize, TlsSerialize, TlsSize)]
pub struct PreSharedKeys {
    pub(crate) psks: TlsVecU16<PreSharedKeyId>,
}

impl PreSharedKeys {
    /// Return the `PreSharedKeyID`s
    pub fn psks(&self) -> &[PreSharedKeyId] {
        self.psks.as_slice()
    }
}

/// `PskLabel` is used in the final concatentation of PSKs before they are
/// injected in the key schedule. struct {
///     PreSharedKeyID id;
///     uint16 index;
///     uint16 count;
/// } PSKLabel;
#[derive(TlsSerialize, TlsSize)]
pub(crate) struct PskLabel<'a> {
    pub(crate) id: &'a PreSharedKeyId,
    pub(crate) index: u16,
    pub(crate) count: u16,
}

impl<'a> PskLabel<'a> {
    /// Create a new `PskLabel`
    fn new(id: &'a PreSharedKeyId, index: u16, count: u16) -> Self {
        Self { id, index, count }
    }
}

/// This contains the `psk-secret` calculated from the PSKs contained in a
/// Commit or a PreSharedKey proposal.
pub struct PskSecret {
    secret: Secret,
}

impl PskSecret {
    /// Create a new `PskSecret` from PSK IDs and PSKs
    ///
    /// ```text
    /// psk_extracted_[i] = KDF.Extract(0, psk_[i])
    /// psk_input_[i] = ExpandWithLabel(psk_extracted_[i], "derived psk", PSKLabel, KDF.Nh)
    ///
    /// psk_secret_[0] = 0
    /// psk_secret_[i] = KDF.Extract(psk_input[i-1], psk_secret_[i-1])
    /// psk_secret     = psk_secret[n]
    /// ```
    pub fn new(
        ciphersuite: Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        psk_ids: &[PreSharedKeyId],
    ) -> Result<Self, PskError> {
        // Check that we don't have too many PSKs
        let num_psks = psk_ids.len();
        if num_psks > u16::MAX as usize {
            return Err(PskError::TooManyKeys);
        }
        let num_psks = num_psks as u16;

        // Fetch the PskBundles from the key store and make sure we have all of them
        let mut psk_bundles: Vec<PskBundle> = Vec::new();
        for psk_id in psk_ids {
            if let Some(psk_bundle) = backend.key_store().read(
                &psk_id
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            ) {
                psk_bundles.push(psk_bundle);
            } else {
                return Err(PskError::KeyNotFound);
            }
        }

        let mls_version = ProtocolVersion::default();
        let mut psk_secret = Secret::zero(ciphersuite, mls_version);
        for ((index, psk_bundle), psk_id) in psk_bundles.iter().enumerate().zip(psk_ids) {
            let zero_secret = Secret::zero(ciphersuite, mls_version);
            let psk_extracted = zero_secret
                .hkdf_extract(backend, psk_bundle.secret())
                .map_err(LibraryError::unexpected_crypto_error)?;
            let psk_label = PskLabel::new(psk_id, index as u16, num_psks)
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?;

            let psk_input = psk_extracted
                .kdf_expand_label(
                    backend,
                    "derived psk",
                    &psk_label,
                    ciphersuite.hash_length(),
                )
                .map_err(LibraryError::unexpected_crypto_error)?;
            psk_secret = psk_input
                .hkdf_extract(backend, &psk_secret)
                .map_err(LibraryError::unexpected_crypto_error)?;
        }
        Ok(Self { secret: psk_secret })
    }

    /// Return the inner secret
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsCryptoProvider) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng, None /* MLS version */)
                .expect("Not enough randomness."),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
        }
    }
}
