//! # Preshared keys.

use std::borrow::Borrow;

use openmls_traits::{random::OpenMlsRand, storage::StorageProvider as StorageProviderTrait};
use serde::{Deserialize, Serialize};
use tls_codec::{Serialize as TlsSerializeTrait, VLBytes};

use super::*;
use crate::{
    group::{GroupEpoch, GroupId},
    schedule::psk::store::ResumptionPskStore,
    storage::{OpenMlsProvider, StorageProvider},
};

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

    // ----- Key Store -----------------------------------------------------------------------------

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

    // ----- Validation ----------------------------------------------------------------------------

    pub(crate) fn validate_in_proposal(self, ciphersuite: Ciphersuite) -> Result<Self, PskError> {
        // ValSem402
        match self.psk() {
            Psk::Resumption(resumption_psk) => {
                if resumption_psk.usage != ResumptionPskUsage::Application {
                    return Err(PskError::UsageMismatch {
                        allowed: vec![ResumptionPskUsage::Application],
                        got: resumption_psk.usage,
                    });
                }
            }
            Psk::External(_) => {}
        };

        // ValSem401
        {
            let expected_nonce_length = ciphersuite.hash_length();
            let got_nonce_length = self.psk_nonce().len();

            if expected_nonce_length != got_nonce_length {
                return Err(PskError::NonceLengthMismatch {
                    expected: expected_nonce_length,
                    got: got_nonce_length,
                });
            }
        }

        Ok(self)
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
    pub(crate) fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        psks: Vec<(impl Borrow<PreSharedKeyId>, Secret)>,
    ) -> Result<Self, PskError> {
        // Check that we don't have too many PSKs
        let num_psks = u16::try_from(psks.len()).map_err(|_| PskError::TooManyKeys)?;

        // Following comments are from `draft-ietf-mls-protocol-19`.
        //
        // psk_secret_[0] = 0
        let mut psk_secret = Secret::zero(ciphersuite);

        for (index, (psk_id, psk)) in psks.into_iter().enumerate() {
            // psk_extracted_[i] = KDF.Extract(0, psk_[i])
            let psk_extracted = {
                let zero_secret = Secret::zero(ciphersuite);
                zero_secret
                    .hkdf_extract(crypto, ciphersuite, &psk)
                    .map_err(LibraryError::unexpected_crypto_error)?
            };

            // psk_input_[i] = ExpandWithLabel( psk_extracted_[i], "derived psk", PSKLabel, KDF.Nh)
            let psk_input = {
                let psk_label = PskLabel::new(psk_id.borrow(), index as u16, num_psks)
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?;

                psk_extracted
                    .kdf_expand_label(
                        crypto,
                        ciphersuite,
                        "derived psk",
                        &psk_label,
                        ciphersuite.hash_length(),
                    )
                    .map_err(LibraryError::unexpected_crypto_error)?
            };

            // psk_secret_[i] = KDF.Extract(psk_input_[i-1], psk_secret_[i-1])
            psk_secret = psk_input
                .hkdf_extract(crypto, ciphersuite, &psk_secret)
                .map_err(LibraryError::unexpected_crypto_error)?;
        }

        Ok(Self { secret: psk_secret })
    }

    /// Return the inner secret
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(any(feature = "test-utils", feature = "crypto-debug", test))]
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

pub(crate) fn load_psks<'p, Storage: StorageProvider>(
    storage: &Storage,
    resumption_psk_store: &ResumptionPskStore,
    psk_ids: &'p [PreSharedKeyId],
) -> Result<Vec<(&'p PreSharedKeyId, Secret)>, PskError> {
    let mut psk_bundles = Vec::new();

    for psk_id in psk_ids.iter() {
        log_crypto!(trace, "PSK store {:?}", resumption_psk_store);

        match &psk_id.psk {
            Psk::Resumption(resumption) => {
                if let Some(psk_bundle) = resumption_psk_store.get(resumption.psk_epoch()) {
                    psk_bundles.push((psk_id, psk_bundle.secret.clone()));
                } else {
                    return Err(PskError::KeyNotFound);
                }
            }
            Psk::External(_) => {
                let psk_bundle: Option<PskBundle> = storage
                    .psk(psk_id.psk())
                    .map_err(|_| PskError::KeyNotFound)?;
                if let Some(psk_bundle) = psk_bundle {
                    psk_bundles.push((psk_id, psk_bundle.secret));
                } else {
                    return Err(PskError::KeyNotFound);
                }
            }
        }
    }

    Ok(psk_bundles)
}

/// This module contains a store that can hold a rollover list of resumption PSKs.
pub mod store {
    use serde::{Deserialize, Serialize};

    use crate::{group::GroupEpoch, schedule::ResumptionPskSecret};

    /// Resumption PSK store.
    ///
    /// This is where the resumption PSKs are kept in a rollover list.
    #[derive(Debug, Serialize, Deserialize)]
    #[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
    pub(crate) struct ResumptionPskStore {
        max_number_of_secrets: usize,
        resumption_psk: Vec<(GroupEpoch, ResumptionPskSecret)>,
        cursor: usize,
    }

    impl ResumptionPskStore {
        /// Creates a new store with a given maximum size of `number_of_secrets`.
        pub(crate) fn new(max_number_of_secrets: usize) -> Self {
            Self {
                max_number_of_secrets,
                resumption_psk: vec![],
                cursor: 0,
            }
        }

        /// Adds a new entry to the store.
        pub(crate) fn add(&mut self, epoch: GroupEpoch, resumption_psk: ResumptionPskSecret) {
            if self.max_number_of_secrets == 0 {
                return;
            }
            let item = (epoch, resumption_psk);
            if self.resumption_psk.len() < self.max_number_of_secrets {
                self.resumption_psk.push(item);
                self.cursor += 1;
            } else {
                self.cursor += 1;
                self.cursor %= self.resumption_psk.len();
                self.resumption_psk[self.cursor] = item;
            }
        }

        /// Searches an entry for a given epoch number and if found, returns the
        /// corresponding resumption psk.
        pub(crate) fn get(&self, epoch: GroupEpoch) -> Option<&ResumptionPskSecret> {
            self.resumption_psk
                .iter()
                .find(|&(e, _s)| e == &epoch)
                .map(|(_e, s)| s)
        }
    }

    #[cfg(test)]
    impl ResumptionPskStore {
        pub(crate) fn cursor(&self) -> usize {
            self.cursor
        }
    }
}
