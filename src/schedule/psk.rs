//! # Pre shared keys.

use super::*;
use crate::group::{GroupEpoch, GroupId};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;

/// enum {
///   reserved(0),
///   external(1),
///   reinit(2),
///   branch(3),
///   (255)
/// } PSKType;
#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[repr(u8)]
pub enum PSKType {
    External = 1,
    Reinit = 2,
    Branch = 3,
}

impl TryFrom<u8> for PSKType {
    type Error = &'static str;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(PSKType::External),
            2 => Ok(PSKType::Reinit),
            3 => Ok(PSKType::Branch),
            _ => Err("Unknown PSK type."),
        }
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ExternalPsk {
    psk_id: Vec<u8>,
}

impl ExternalPsk {
    pub fn new(psk_id: Vec<u8>) -> Self {
        Self { psk_id }
    }
    pub fn psk_id(&self) -> &[u8] {
        &self.psk_id
    }
}

#[cfg(test)]
pub struct ExternalPskBundle {
    secret: Secret,
    nonce: Vec<u8>,
    external_psk: ExternalPsk,
}

#[cfg(test)]
impl ExternalPskBundle {
    pub fn new(ciphersuite: &Ciphersuite, secret: Secret, psk_id: Vec<u8>) -> Self {
        Self {
            secret,
            nonce: Ciphersuite::random_vec(ciphersuite.hash_length()),
            external_psk: ExternalPsk { psk_id },
        }
    }
    pub fn to_presharedkey_id(&self) -> PreSharedKeyID {
        PreSharedKeyID {
            psk_type: PSKType::External,
            psk: Psk::External(self.external_psk.clone()),
            psk_nonce: self.nonce.clone(),
        }
    }
    pub fn secret(&self) -> &Secret {
        &self.secret
    }
}
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ReinitPsk {
    pub(crate) psk_group_id: GroupId,
    pub(crate) psk_epoch: GroupEpoch,
}

impl ReinitPsk {
    pub fn psk_group_id(&self) -> &GroupId {
        &self.psk_group_id
    }
    pub fn psk_epoch(&self) -> GroupEpoch {
        self.psk_epoch
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BranchPsk {
    pub(crate) psk_group_id: GroupId,
    pub(crate) psk_epoch: GroupEpoch,
}

impl BranchPsk {
    pub fn psk_group_id(&self) -> &GroupId {
        &self.psk_group_id
    }
    pub fn psk_epoch(&self) -> GroupEpoch {
        self.psk_epoch
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum Psk {
    External(ExternalPsk),
    Reinit(ReinitPsk),
    Branch(BranchPsk),
}

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
pub struct PreSharedKeyID {
    pub(crate) psk_type: PSKType,
    pub(crate) psk: Psk,
    pub(crate) psk_nonce: Vec<u8>,
}

impl PreSharedKeyID {
    pub fn new(psk_type: PSKType, psk: Psk, psk_nonce: Vec<u8>) -> Self {
        Self {
            psk_type,
            psk,
            psk_nonce,
        }
    }
    pub fn psktype(&self) -> &PSKType {
        &self.psk_type
    }
    pub fn psk(&self) -> &Psk {
        &self.psk
    }
    pub fn psk_nonce(&self) -> &[u8] {
        &self.psk_nonce
    }
}

/// struct {
///     PreSharedKeyID psks<0..2^16-1>;
/// } PreSharedKeys;
pub struct PreSharedKeys {
    pub(crate) psks: Vec<PreSharedKeyID>,
}

impl PreSharedKeys {
    pub fn psks(&self) -> &Vec<PreSharedKeyID> {
        &self.psks
    }
}

/// struct {
///     PreSharedKeyID id;
///     uint16 index;
///     uint16 count;
/// } PSKLabel;
pub(crate) struct PskLabel<'a> {
    pub(crate) id: &'a PreSharedKeyID,
    pub(crate) index: u16,
    pub(crate) count: u16,
}

impl<'a> PskLabel<'a> {
    /// Create a new `PskLabel`
    fn new(id: &'a PreSharedKeyID, index: u16, count: u16) -> Self {
        Self { id, index, count }
    }
}

/// This contains the `psk-secret` calculated from the PSKs contained in a Commit or a PreSharedKey proposal.
pub struct PskSecret {
    secret: Secret,
}

impl PskSecret {
    /// Create a new `PskSecret` from PSK IDs and PSKs
    pub fn new(ciphersuite: &Ciphersuite, psk_ids: &[PreSharedKeyID], psks: &[Secret]) -> Self {
        let mut secret = vec![];
        for (index, psk) in psks.iter().enumerate() {
            let psk_input = ciphersuite.hkdf_extract(None, psk);
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
        Self {
            secret: Secret::from(secret),
        }
    }

    /// Return the inner secret
    pub fn secret(&self) -> &Secret {
        &self.secret
    }
}
