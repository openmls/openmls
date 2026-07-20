//! # Preshared keys.

#[cfg(feature = "migration-export")]
use openmls_traits::storage::StorageProvider as StorageProviderTrait;
use serde::{Deserialize, Serialize};
use tls_codec::VLBytes;

use super::*;
use crate::group::{GroupEpoch, GroupId};
#[cfg(feature = "migration-export")]
use crate::storage::OpenMlsProvider;

#[cfg(feature = "migration-export")]
use crate::schedule::errors::PskError;

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
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
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

/// External PSK.
#[derive(
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Clone,
    Hash,
    Deserialize,
    Serialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct ExternalPsk {
    psk_id: VLBytes,
}

/// Contains the secret part of the PSK as well as the
/// public part that is used as a marker for injection into the key schedule.
#[derive(Serialize, Deserialize, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub(crate) struct PskBundle {
    secret: Secret,
}

/// Resumption PSK.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    Serialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct ResumptionPsk {
    pub(crate) usage: ResumptionPskUsage,
    pub(crate) psk_group_id: GroupId,
    pub(crate) psk_epoch: GroupEpoch,
}

/// The different PSK types.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    Serialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
#[repr(u8)]
pub enum Psk {
    /// An external PSK provided by the application.
    #[tls_codec(discriminant = 1)]
    External(ExternalPsk),
    /// A resumption PSK derived from the MLS key schedule.
    #[tls_codec(discriminant = 2)]
    Resumption(ResumptionPsk),
}

/// ```c
/// // draft-ietf-mls-protocol-19
/// enum {
///   reserved(0),
///   external(1),
///   resumption(2),
///   (255)
/// } PSKType;
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PskType {
    /// An external PSK.
    External = 1,
    /// A resumption PSK.
    Resumption = 2,
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
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Deserialize,
    Serialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct PreSharedKeyId {
    pub(crate) psk: Psk,
    pub(crate) psk_nonce: VLBytes,
}

impl PreSharedKeyId {
    #[cfg(feature = "migration-export")]
    /// Save this `PreSharedKeyId` in the keystore.
    ///
    /// Note: The nonce is not saved as it must be unique for each time it's being applied.
    pub fn store<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        psk: &[u8],
    ) -> Result<(), PskError> {
        let psk_bundle = {
            let secret = Secret::from_slice(psk);

            PskBundle { secret }
        };

        provider
            .storage()
            .write_psk(&self.psk, &psk_bundle)
            .map_err(|_| PskError::Storage)
    }
}

/// `PskLabel` is used in the final concatentation of PSKs before they are
/// injected in the key schedule.
///
/// ```c
/// // draft-ietf-mls-protocol-19
/// struct {
///     PreSharedKeyID id;
///     uint16 index;
///     uint16 count;
/// } PSKLabel;
/// ```
#[derive(TlsSerialize, TlsSize)]
pub(crate) struct PskLabel<'a> {
    pub(crate) id: &'a PreSharedKeyId,
    pub(crate) index: u16,
    pub(crate) count: u16,
}

/// This contains the `psk-secret` calculated from the PSKs contained in a
/// Commit or a PreSharedKey proposal.
#[derive(Clone)]
pub struct PskSecret {
    secret: Secret,
}

/// This module contains a store that can hold a rollover list of resumption PSKs.
pub mod store {
    use serde::{Deserialize, Serialize};

    use crate::{group::GroupEpoch, schedule::ResumptionPskSecret};

    /// Resumption PSK store.
    ///
    /// This is where the resumption PSKs are kept in a rollover list.
    #[derive(Debug, Serialize, Deserialize)]
    pub(crate) struct ResumptionPskStore {
        max_number_of_secrets: usize,
        resumption_psk: Vec<(GroupEpoch, ResumptionPskSecret)>,
        cursor: usize,
    }
}
