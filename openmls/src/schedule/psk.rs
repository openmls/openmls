//! # Preshared keys.

use openmls_traits::{
    key_store::{MlsEntity, MlsEntityId, OpenMlsKeyStore},
    random::OpenMlsRand,
    OpenMlsCryptoProvider,
};
use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as TlsSerializeTrait, VLBytes};

use super::*;
use crate::group::{GroupEpoch, GroupId};

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
    TlsSerialize,
    TlsSize,
)]
pub struct ExternalPsk {
    psk_id: VLBytes,
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
#[derive(Serialize, Deserialize, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct PskBundle {
    secret: Secret,
}

impl PskBundle {
    /// Return the secret
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }
}

#[cfg(test)]
impl PskBundle {
    /// Create a new bundle
    pub(crate) fn new(secret: Secret) -> Result<Self, CryptoError> {
        Ok(Self { secret })
    }
}

impl MlsEntity for PskBundle {
    const ID: MlsEntityId = MlsEntityId::PskBundle;
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
    TlsSerialize,
    TlsSize,
)]
pub struct ResumptionPsk {
    pub(crate) usage: ResumptionPskUsage,
    pub(crate) psk_group_id: GroupId,
    pub(crate) psk_epoch: GroupEpoch,
}

impl ResumptionPsk {
    /// Create a new `ResumptionPsk`
    pub fn new(usage: ResumptionPskUsage, psk_group_id: GroupId, psk_epoch: GroupEpoch) -> Self {
        Self {
            usage,
            psk_group_id,
            psk_epoch,
        }
    }

    /// Return the usage
    pub fn usage(&self) -> ResumptionPskUsage {
        self.usage
    }

    /// Return the `GroupId`
    pub fn psk_group_id(&self) -> &GroupId {
        &self.psk_group_id
    }

    /// Return the `GroupEpoch`
    pub fn psk_epoch(&self) -> GroupEpoch {
        self.psk_epoch
    }
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
    External = 1,
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
    TlsSerialize,
    TlsSize,
)]
pub struct PreSharedKeyId {
    pub(crate) psk: Psk,
    pub(crate) psk_nonce: VLBytes,
}

impl PreSharedKeyId {
    /// Construct a `PreSharedKeyID` with a random nonce.
    pub fn new(
        ciphersuite: Ciphersuite,
        rand: &impl OpenMlsRand,
        psk: Psk,
    ) -> Result<Self, CryptoError> {
        let psk_nonce = rand
            .random_vec(ciphersuite.hash_length())
            .map_err(|_| CryptoError::InsufficientRandomness)?
            .into();

        Ok(Self { psk, psk_nonce })
    }

    /// Construct an external `PreSharedKeyID`.
    pub fn external(psk_id: Vec<u8>, psk_nonce: Vec<u8>) -> Self {
        let psk = Psk::External(ExternalPsk::new(psk_id));

        Self {
            psk,
            psk_nonce: psk_nonce.into(),
        }
    }

    /// Construct a resumption `PreSharedKeyID`.
    pub fn resumption(
        usage: ResumptionPskUsage,
        psk_group_id: GroupId,
        psk_epoch: GroupEpoch,
        psk_nonce: Vec<u8>,
    ) -> Self {
        let psk = Psk::Resumption(ResumptionPsk::new(usage, psk_group_id, psk_epoch));

        Self {
            psk,
            psk_nonce: psk_nonce.into(),
        }
    }

    /// Return the PSK.
    pub fn psk(&self) -> &Psk {
        &self.psk
    }

    /// Return the PSK nonce.
    pub fn psk_nonce(&self) -> &[u8] {
        self.psk_nonce.as_slice()
    }

    /// Save this `PreSharedKeyId` in the keystore.
    ///
    /// Note: The nonce is not saved as it must be unique for each time it's being applied.
    pub fn write_to_key_store<KeyStore: OpenMlsKeyStore>(
        &self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        ciphersuite: Ciphersuite,
        psk: &[u8],
    ) -> Result<(), PskError> {
        let keystore_id = self.keystore_id()?;

        let psk_bundle = {
            let secret = Secret::from_slice(psk, ProtocolVersion::default(), ciphersuite);

            PskBundle { secret }
        };

        backend
            .key_store()
            .store(&keystore_id, &psk_bundle)
            .map_err(|_| PskError::KeyStore)
    }

    pub(crate) fn keystore_id(&self) -> Result<Vec<u8>, LibraryError> {
        let psk_id_with_empty_nonce = PreSharedKeyId {
            psk: self.psk.clone(),
            psk_nonce: VLBytes::new(vec![]),
        };

        log::trace!(
            "keystore id: {:x?}",
            psk_id_with_empty_nonce.tls_serialize_detached()
        );

        psk_id_with_empty_nonce
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)
    }
}

#[cfg(test)]
impl PreSharedKeyId {
    pub(crate) fn new_with_nonce(psk: Psk, psk_nonce: Vec<u8>) -> Self {
        Self {
            psk,
            psk_nonce: psk_nonce.into(),
        }
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

impl<'a> PskLabel<'a> {
    /// Create a new `PskLabel`
    fn new(id: &'a PreSharedKeyId, index: u16, count: u16) -> Self {
        Self { id, index, count }
    }
}

/// This contains the `psk-secret` calculated from the PSKs contained in a
/// Commit or a PreSharedKey proposal.
#[derive(Clone)]
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
            if let Some(psk_bundle) = backend.key_store().read(&psk_id.keystore_id()?) {
                psk_bundles.push(psk_bundle);
            } else {
                debug_assert!(false, "PSK not found in the key store.");
                return Err(PskError::KeyNotFound);
            }
        }

        let mls_version = ProtocolVersion::default();

        // Following comments are from `draft-ietf-mls-protocol-19`.
        //
        // psk_secret_[0] = 0
        let mut psk_secret = Secret::zero(ciphersuite, mls_version);

        for ((index, psk_bundle), psk_id) in psk_bundles.iter().enumerate().zip(psk_ids) {
            // psk_extracted_[i] = KDF.Extract(0, psk_[i])
            let psk_extracted = {
                let zero_secret = Secret::zero(ciphersuite, mls_version);
                zero_secret
                    .hkdf_extract(backend, psk_bundle.secret())
                    .map_err(LibraryError::unexpected_crypto_error)?
            };

            // psk_input_[i] = ExpandWithLabel( psk_extracted_[i], "derived psk", PSKLabel, KDF.Nh)
            let psk_input = {
                let psk_label = PskLabel::new(psk_id, index as u16, num_psks)
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?;

                psk_extracted
                    .kdf_expand_label(
                        backend,
                        "derived psk",
                        &psk_label,
                        ciphersuite.hash_length(),
                    )
                    .map_err(LibraryError::unexpected_crypto_error)?
            };

            // psk_secret_[i] = KDF.Extract(psk_input_[i-1], psk_secret_[i-1])
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
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

#[cfg(any(feature = "test-utils", test))]
impl From<Secret> for PskSecret {
    fn from(secret: Secret) -> Self {
        Self { secret }
    }
}
