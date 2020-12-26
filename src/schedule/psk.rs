//#![allow(dead_code)]
//! # Pre shared keys.

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
    pub(crate) psk_id: Vec<u8>,
}

impl ExternalPsk {
    pub fn psk_id(&self) -> &[u8] {
        &self.psk_id
    }
}
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct ReinitPsk {
    pub(crate) psk_group_id: Vec<u8>,
    pub(crate) psk_epoch: u64,
}

impl ReinitPsk {
    pub fn psk_group_id(&self) -> &[u8] {
        &self.psk_group_id
    }
    pub fn psk_epoch(&self) -> u64 {
        self.psk_epoch
    }
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct BranchPsk {
    pub(crate) psk_group_id: Vec<u8>,
    pub(crate) psk_epoch: u64,
}

impl BranchPsk {
    pub fn psk_group_id(&self) -> &[u8] {
        &self.psk_group_id
    }
    pub fn psk_epoch(&self) -> u64 {
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
    pub(crate) psktype: PSKType,
    pub(crate) psk: Psk,
    pub(crate) psk_nonce: Vec<u8>,
}

impl PreSharedKeyID {
    pub fn psktype(&self) -> &PSKType {
        &self.psktype
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
