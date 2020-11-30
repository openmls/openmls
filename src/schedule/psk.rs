#![allow(dead_code)]
//! # Pre shared keys.

// TODO: Implement PSK support #141.

/// enum {
///   reserved(0),
///   external(1),
///   reinit(2),
///   branch(3),
///   (255)
/// } PSKType;
#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub(crate) enum PSKType {
    Reserved = 0,
    External = 1,
    Reinit = 2,
    Branch = 3,
}

struct ExternalPsk {
    psk_id: Vec<u8>,
}
struct ReinitPsk {
    psk_group_id: Vec<u8>,
    psk_epoch: u64,
}
struct BranchPsk {
    psk_group_id: Vec<u8>,
    psk_epoch: u64,
}

enum Psk {
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
struct PreSharedKeyID {
    psktype: PSKType,
}

/// struct {
///     PreSharedKeyID psks<0..2^16-1>;
/// } PreSharedKeys;
pub(crate) struct PreSharedKeys {
    psks: Vec<PreSharedKeyID>,
}
