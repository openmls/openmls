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
use crate::utils::randombytes;
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

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
#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
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

/// External PSK.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ExternalPsk {
    psk_id: Vec<u8>,
}

impl ExternalPsk {
    /// Create a new `ExternalPsk` from a PSK ID
    pub fn new(psk_id: Vec<u8>) -> Self {
        Self { psk_id }
    }
    /// Return the PSK ID
    pub fn psk_id(&self) -> &[u8] {
        &self.psk_id
    }
}

/// External PSK Bundle. This contains the secret part of the PSK as well as the
/// public part that is used as a marker for injection into the key schedule.
pub struct ExternalPskBundle {
    secret: Secret,
    nonce: Vec<u8>,
    external_psk: ExternalPsk,
}

impl ExternalPskBundle {
    /// Create a new bundle
    pub fn new(ciphersuite: &Ciphersuite, secret: Secret, psk_id: Vec<u8>) -> Self {
        Self {
            secret,
            nonce: randombytes(ciphersuite.hash_length()),
            external_psk: ExternalPsk { psk_id },
        }
    }
    /// Return the `PreSharedKeyID`
    pub fn to_presharedkey_id(&self) -> PreSharedKeyId {
        PreSharedKeyId {
            psk_type: PskType::External,
            psk: Psk::External(self.external_psk.clone()),
            psk_nonce: self.nonce.clone(),
        }
    }
    /// Return the secret
    pub fn secret(&self) -> &Secret {
        &self.secret
    }
}
/// ReInit PSK.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
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
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct PreSharedKeyId {
    pub(crate) psk_type: PskType,
    pub(crate) psk: Psk,
    pub(crate) psk_nonce: Vec<u8>,
}

impl PreSharedKeyId {
    /// Create a new `PreSharedKeyID`
    pub fn new(psk_type: PskType, psk: Psk, psk_nonce: Vec<u8>) -> Self {
        Self {
            psk_type,
            psk,
            psk_nonce,
        }
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
        &self.psk_nonce
    }
}

/// `PreSharedKeys` is a vector of `PreSharedKeyID`s.
/// struct {
///     PreSharedKeyID psks<0..2^16-1>;
/// } PreSharedKeys;
pub struct PreSharedKeys {
    pub(crate) psks: Vec<PreSharedKeyId>,
}

impl PreSharedKeys {
    /// Return the `PreSharedKeyID`s
    pub fn psks(&self) -> &Vec<PreSharedKeyId> {
        &self.psks
    }
}

/// `PskLabel` is used in the final concatentation of PSKs before they are
/// injected in the key schedule. struct {
///     PreSharedKeyID id;
///     uint16 index;
///     uint16 count;
/// } PSKLabel;
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
    pub fn new(
        ciphersuite: &Ciphersuite,
        psk_ids: &[PreSharedKeyId],
        psks: &[Secret],
    ) -> Result<Self, PskSecretError> {
        if psk_ids.len() != psks.len() {
            return Err(PskSecretError::DifferentLength);
        }
        if psks.len() > u16::MAX as usize {
            return Err(PskSecretError::TooManyKeys);
        }
        let mut secret = vec![];
        for (index, psk) in psks.iter().enumerate() {
            let zero_secret = Secret::from(zero(ciphersuite.hash_length()));
            let psk_input = ciphersuite.hkdf_extract(&zero_secret, Some(psk));
            let psk_label = PskLabel::new(&psk_ids[index], index as u16, psks.len() as u16)
                .encode_detached()
                // It is safe to unwrap here, because the struct contains no vectors
                .unwrap();

            let psk_secret = psk_input.kdf_expand_label(
                ciphersuite,
                "derived psk",
                &psk_label,
                ciphersuite.hash_length(),
            );
            secret.extend_from_slice(psk_secret.to_bytes());
        }
        Ok(Self {
            secret: Secret::from(secret),
        })
    }

    /// Return the inner secret
    pub fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(any(feature = "expose-test-vectors", test))]
    pub(crate) fn random(length: usize) -> Self {
        Self {
            secret: Secret::random(length),
        }
    }

    #[cfg(any(feature = "expose-test-vectors", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
    }

    #[cfg(any(feature = "expose-test-vectors", test))]
    pub(crate) fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
        }
    }

    #[cfg(any(feature = "expose-test-vectors", test))]
    pub(crate) fn from_slice(b: &[u8]) -> Self {
        Self { secret: b.into() }
    }
}
