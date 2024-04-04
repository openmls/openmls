use tls_codec::VLBytes;

use super::{GroupEpoch, GroupId};

pub const PSK_TYPE_EXTERNAL: u8 = 1;
pub const PSK_TYPE_RESUMPTION: u8 = 2;

/// Resumption PSK usage.
///
/// ```c
/// // draft-ietf-mls-protocol-19
/// enum {
///   reserved(0),
///   application(1),
///   reinit(2),
///   branch(3),
///   (255)
/// } ResumptionPSKUsage;
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum ResumptionPskUsage {
    /// Application.
    Application = 1,
    /// Resumption PSK used for group reinitialization.
    ///
    /// Note: "Resumption PSKs with usage `reinit` MUST NOT be used in other contexts (than reinitialization)."
    Reinit = 2,
    /// Resumption PSK used for subgroup branching.
    ///
    /// Note: "Resumption PSKs with usage `branch` MUST NOT be used in other contexts (than subgroup branching)."
    Branch = 3,
}

/// A `PreSharedKeyID` is used to uniquely identify the PSKs that get injected
/// in the key schedule.
///
/// ```c
/// // draft-ietf-mls-protocol-19
/// struct {
///   PSKType psktype;
///   select (PreSharedKeyID.psktype) {
///     case external:
///       opaque psk_id<V>;
///
///     case resumption:
///       ResumptionPSKUsage usage;
///       opaque psk_group_id<V>;
///       uint64 psk_epoch;
///   };
///   opaque psk_nonce<V>;
/// } PreSharedKeyID;
/// ```
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum PreSharedKeyId {
    /// An external PSK provided by the application.
    External(ExternalPsk) = PSK_TYPE_EXTERNAL,
    /// A resumption PSK derived from the MLS key schedule.
    Resumption(ResumptionPsk) = PSK_TYPE_RESUMPTION,
}

/// External PSK.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
pub struct ExternalPsk {
    pub(super) psk_id: VLBytes,
    pub(super) psk_nonce: VLBytes,
}

/// Resumption PSK.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResumptionPsk {
    pub(super) usage: ResumptionPskUsage,
    pub(super) psk_group_id: GroupId,
    pub(super) psk_epoch: GroupEpoch,
    pub(super) psk_nonce: VLBytes,
}
