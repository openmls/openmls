//! # Key schedule
//!
//! This module contains the types and implementations for key schedule operations.
//! It exposes the [`EpochAuthenticator`] & [`ResumptionPskSecret`].

// Internal documentation
//
// The key schedule is introduced in Section 9 of the
// MLS specification. The key schedule evolves in epochs, where in each epoch
// new key material is injected.
//
// The flow of the key schedule is as follows (from Section 9 of the MLS
// specification):
//
// ```text
//                  init_secret_[n-1]
//                         |
//                         V
//    commit_secret -> KDF.Extract
//                         |
//                         V
//                   DeriveSecret(., "joiner")
//                         |
//                         V
//                    joiner_secret
//                         |
//                         V
// psk_secret (or 0) -> KDF.Extract (= intermediary_secret)
//                         |
//                         +--> DeriveSecret(., "welcome")
//                         |    = welcome_secret
//                         |
//                         V
//                   ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//                         |
//                         V
//                    epoch_secret
//                         |
//                         +--> DeriveSecret(., <label>)
//                         |    = <secret>
//                         |
//                         V
//                   DeriveSecret(., "init")
//                         |
//                         V
//                   init_secret_[n]
// ```
//
// Each of the secrets in the key schedule (with exception of the
// welcome_secret) is represented by its own struct to ensure that the keys are
// not confused with one-another and/or that the schedule is not derived
// out-of-order.
//
// ## The real key schedules
// The key schedule as described in the spec isn't really one key schedule.
// The `joiner_secret` is an intermediate value *and* an output value. This
// must never be the case within a key schedule. The actual key schedule is
// therefore only the second half starting with the `joiner_secret`, which
// indeed is what happens when starting a group from a welcome message.
//
// The `joiner_secret` is computed as
//
// ```text
//     DeriveSecret(KDF.Extract(init_secret_[n-1], commit_secret), "joiner")
// ```
//
// or
//
// ```text
//                  init_secret_[n-1]
//                         |
//                         V
//    commit_secret -> KDF.Extract
//                         |
//                         V
//                   DeriveSecret(., "joiner")
//                         |
//                         V
//                    joiner_secret
// ```
//
// The remainder of the key schedule then starts with the `joiner_secret` and
// `psk_secret`. Note that the following graph also adds the `GroupContext_[n]`
// as input, which is omitted in the spec.
// Further note that the derivation of the secrets from the `epoch_secret` is
// simplified here.
//
// ```text
//                    joiner_secret
//                         |
//                         V
// psk_secret (or 0) -> KDF.Extract
//                         |
//                         +--> DeriveSecret(., "welcome")
//                         |    = welcome_secret
//                         |
//                         V
// GroupContext_[n] -> ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//                         |
//                         V
//                    epoch_secret
//                         |
//                         v
//                 DeriveSecret(., <label>)
//                     = <secret>
// ```
//
// with
//
// ```text
// | secret                  | label           |
// |:------------------------|:----------------|
// | `init_secret`           | "init"          |
// | `sender_data_secret`    | "sender data"   |
// | `encryption_secret`     | "encryption"    |
// | `exporter_secret`       | "exporter"      |
// | `epoch_authenticator`   | "authentication"|
// | `external_secret`       | "external"      |
// | `confirmation_key`      | "confirm"       |
// | `membership_key`        | "membership"    |
// | `resumption_psk`        | "resumption"    |
// ```

use openmls_traits::{crypto::OpenMlsCrypto, types::*};
use serde::{Deserialize, Serialize};
use tls_codec::{TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize};

use crate::{
    binary_tree::array_representation::{LeafNodeIndex, TreeSize},
    ciphersuite::{AeadKey, AeadNonce, HpkePrivateKey, Mac, Secret},
    error::LibraryError,
    framing::{mls_content::AuthenticatedContentTbm, MembershipTag},
    group::GroupContext,
    messages::{ConfirmationTag, PathSecret},
    tree::secret_tree::SecretTree,
    versions::ProtocolVersion,
};

// Public
pub mod errors;
pub mod psk;

// Crate
pub(crate) mod message_secrets;

// Private
use errors::*;
use message_secrets::MessageSecrets;
use openmls_traits::random::OpenMlsRand;
use psk::PskSecret;

// Tests and kats
#[cfg(any(feature = "test-utils", test))]
pub mod tests_and_kats;

// Public types
pub use psk::{ExternalPsk, PreSharedKeyId, Psk};

/// A group secret that can be used among members to prove that a member was
/// part of a group in a given epoch.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Eq, PartialEq))]
pub struct ResumptionPskSecret {
    secret: Secret,
}

impl ResumptionPskSecret {
    /// Derive an `ResumptionPsk` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "resumption")?;
        Ok(Self { secret })
    }

    /// Returns the secret as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// A secret that can be used among members to make sure everyone has the same
/// group state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Eq, PartialEq, Clone))]
pub struct EpochAuthenticator {
    secret: Secret,
}

impl EpochAuthenticator {
    /// Derive an `EpochAuthenticator` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "authentication")?;
        Ok(Self { secret })
    }

    /// Returns the secret as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

// Crate-only types

#[derive(Debug, Default, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(any(feature = "test-utils", test), derive(Clone))]
pub(crate) struct CommitSecret {
    secret: Secret,
}

impl From<PathSecret> for CommitSecret {
    fn from(path_secret: PathSecret) -> Self {
        CommitSecret {
            secret: path_secret.secret(),
        }
    }
}

impl CommitSecret {
    /// Create a CommitSecret consisting of an all-zero string of length
    /// `hash_length`.
    pub(crate) fn zero_secret(ciphersuite: Ciphersuite) -> Self {
        CommitSecret {
            secret: Secret::zero(ciphersuite),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// The `InitSecret` is used to connect the next epoch to the current one.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct InitSecret {
    secret: Secret,
}

impl From<Secret> for InitSecret {
    fn from(secret: Secret) -> Self {
        Self { secret }
    }
}

/// Creates a string from the given MLS `ProtocolVersion` for the computation of
/// the `init_secret` when creating or processing a commit with an external init
/// proposal. TODO: #628.
fn hpke_info_from_version(version: ProtocolVersion) -> &'static str {
    match version {
        ProtocolVersion::Mls10 => "MLS 1.0 external init secret",
        _ => "<OpenMLS reserved; Don't use this.>",
    }
}

impl InitSecret {
    /// Derive an `InitSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "init")?;
        log_crypto!(trace, "Init secret: {:x?}", secret);
        Ok(InitSecret { secret })
    }

    /// Sample a fresh, random `InitSecret` for the creation of a new group.
    pub(crate) fn random(
        ciphersuite: Ciphersuite,
        rand: &impl OpenMlsRand,
    ) -> Result<Self, CryptoError> {
        Ok(InitSecret {
            secret: Secret::random(ciphersuite, rand)?,
        })
    }

    /// Create an `InitSecret` and the corresponding `kem_output` from a group info.
    pub(crate) fn from_group_context(
        crypto: &impl OpenMlsCrypto,
        group_context: &GroupContext,
        external_pub: &[u8],
    ) -> Result<(Self, Vec<u8>), KeyScheduleError> {
        let ciphersuite = group_context.ciphersuite();
        let version = group_context.protocol_version();
        let (kem_output, raw_init_secret) = crypto.hpke_setup_sender_and_export(
            ciphersuite.hpke_config(),
            external_pub,
            &[],
            hpke_info_from_version(version).as_bytes(),
            ciphersuite.hash_length(),
        )?;
        Ok((
            InitSecret {
                secret: Secret::from_slice(&raw_init_secret),
            },
            kem_output,
        ))
    }

    /// Create an `InitSecret` from a `kem_output`.
    pub(crate) fn from_kem_output(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        version: ProtocolVersion,
        external_priv: &HpkePrivateKey,
        kem_output: &[u8],
    ) -> Result<Self, LibraryError> {
        let raw_init_secret = crypto
            .hpke_setup_receiver_and_export(
                ciphersuite.hpke_config(),
                kem_output,
                external_priv,
                &[],
                hpke_info_from_version(version).as_bytes(),
                ciphersuite.hash_length(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;
        Ok(InitSecret {
            secret: Secret::from_slice(&raw_init_secret),
        })
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

#[derive(Debug, TlsDeserialize, TlsDeserializeBytes, TlsSerialize, TlsSize)]
pub(crate) struct JoinerSecret {
    secret: Secret,
}

impl JoinerSecret {
    /// Derive a `JoinerSecret` from an optional `CommitSecret` and an
    /// `EpochSecrets` object, which contains the necessary `InitSecret`. The
    /// `CommitSecret` needs to be present if the current commit is not a
    /// partial commit.
    pub(crate) fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        commit_secret_option: impl Into<Option<CommitSecret>>,
        init_secret: &InitSecret,
        serialized_group_context: &[u8],
    ) -> Result<Self, CryptoError> {
        let intermediate_secret = init_secret.secret.hkdf_extract(
            crypto,
            ciphersuite,
            commit_secret_option.into().as_ref().map(|cs| &cs.secret),
        )?;
        let secret = intermediate_secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "joiner",
            serialized_group_context,
            ciphersuite.hash_length(),
        )?;
        log_crypto!(trace, "Joiner secret: {:x?}", secret);
        Ok(JoinerSecret { secret })
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(test)]
    pub(crate) fn random(ciphersuite: Ciphersuite, rand: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rand).expect("Not enough randomness."),
        }
    }
}

// Different states of the key schedule
#[derive(Debug, PartialEq)]
enum State {
    Initial,
    Context,
    Done,
}

pub(crate) struct KeySchedule {
    ciphersuite: Ciphersuite,
    intermediate_secret: Option<IntermediateSecret>,
    epoch_secret: Option<EpochSecret>,
    state: State,
}

impl KeySchedule {
    /// Initialize the key schedule and return it.
    pub(crate) fn init(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        joiner_secret: &JoinerSecret,
        psk: PskSecret,
    ) -> Result<Self, LibraryError> {
        log::debug!("Initializing the key schedule with {:?} ...", ciphersuite);
        log_crypto!(
            trace,
            "  joiner_secret: {:x?}",
            joiner_secret.secret.as_slice()
        );
        let intermediate_secret = IntermediateSecret::new(crypto, ciphersuite, joiner_secret, psk)
            .map_err(LibraryError::unexpected_crypto_error)?;
        Ok(Self {
            ciphersuite,
            intermediate_secret: Some(intermediate_secret),
            epoch_secret: None,
            state: State::Initial,
        })
    }

    /// Derive the welcome secret.
    /// Note that this has to be called before the context is added.
    pub(crate) fn welcome(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<WelcomeSecret, KeyScheduleError> {
        if self.state != State::Initial || self.intermediate_secret.is_none() {
            log::error!("Trying to derive a welcome secret while not in the initial state.");
            return Err(KeyScheduleError::InvalidState(ErrorState::Init));
        }

        // We can return a library error here, because there must be a mistake in the state machine
        let intermediate_secret = self
            .intermediate_secret
            .as_ref()
            .ok_or_else(|| LibraryError::custom("state machine error"))?;

        Ok(WelcomeSecret::new(
            crypto,
            ciphersuite,
            intermediate_secret,
        )?)
    }

    /// Add the group context to the key schedule.
    pub(crate) fn add_context(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        serialized_group_context: &[u8],
    ) -> Result<(), KeyScheduleError> {
        log::trace!(
            "Adding context to key schedule. {:?}",
            serialized_group_context
        );
        if self.state != State::Initial || self.intermediate_secret.is_none() {
            log::error!(
                "Trying to add context to the key schedule while not in the initial state."
            );
            return Err(KeyScheduleError::InvalidState(ErrorState::Init));
        }
        self.state = State::Context;

        // We can return a library error here, because there must be a mistake in the state machine
        let intermediate_secret = self
            .intermediate_secret
            .take()
            .ok_or_else(|| LibraryError::custom("state machine error"))?;

        log_crypto!(
            trace,
            "  intermediate_secret: {:x?}",
            intermediate_secret.secret.as_slice()
        );

        self.epoch_secret = Some(EpochSecret::new(
            self.ciphersuite,
            crypto,
            intermediate_secret,
            serialized_group_context,
        )?);
        self.intermediate_secret = None;
        Ok(())
    }

    /// Derive the epoch secrets.
    /// If the `with_init_secret` argument is `true`, the init secret is derived and
    /// part of the `EpochSecrets`. Otherwise not.
    pub(crate) fn epoch_secrets(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<EpochSecrets, KeyScheduleError> {
        if self.state != State::Context || self.epoch_secret.is_none() {
            log::error!("Trying to derive the epoch secrets while not in the right state.");
            return Err(KeyScheduleError::InvalidState(ErrorState::Context));
        }
        self.state = State::Done;

        let epoch_secret = match self.epoch_secret.take() {
            Some(epoch_secret) => epoch_secret,
            // We can return a library error here, because there must be a mistake in the state machine
            None => return Err(LibraryError::custom("state machine error").into()),
        };

        Ok(EpochSecrets::new(crypto, ciphersuite, epoch_secret)?)
    }
}

/// The intermediate secret includes the optional PSK and is used to later
/// derive the welcome secret and epoch secret
struct IntermediateSecret {
    secret: Secret,
}

impl IntermediateSecret {
    /// Derive an `IntermediateSecret` from a `JoinerSecret` and an optional
    /// PSK.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        joiner_secret: &JoinerSecret,
        psk: PskSecret,
    ) -> Result<Self, CryptoError> {
        log_crypto!(trace, "PSK input: {:x?}", psk.as_slice());
        let secret = joiner_secret
            .secret
            .hkdf_extract(crypto, ciphersuite, psk.secret())?;
        log_crypto!(trace, "Intermediate secret: {:x?}", secret);
        Ok(Self { secret })
    }
}

pub(crate) struct WelcomeSecret {
    secret: Secret,
}

impl WelcomeSecret {
    /// Derive a `WelcomeSecret` from to decrypt a `Welcome` message.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        intermediate_secret: &IntermediateSecret,
    ) -> Result<Self, CryptoError> {
        let secret = intermediate_secret
            .secret
            .derive_secret(crypto, ciphersuite, "welcome")?;
        log_crypto!(trace, "Welcome secret: {:x?}", secret);
        Ok(WelcomeSecret { secret })
    }

    /// Derive an `AeadKey` and an `AeadNonce` from the `WelcomeSecret`,
    /// consuming it in the process.
    pub(crate) fn derive_welcome_key_nonce(
        self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(AeadKey, AeadNonce), CryptoError> {
        let welcome_nonce = self.derive_aead_nonce(crypto, ciphersuite)?;
        let welcome_key = self.derive_aead_key(crypto, ciphersuite)?;
        Ok((welcome_key, welcome_nonce))
    }

    /// Derive a new AEAD key from a `WelcomeSecret`.
    fn derive_aead_key(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<AeadKey, CryptoError> {
        log::trace!("WelcomeSecret.derive_aead_key with {}", ciphersuite);
        let aead_secret = self.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "key",
            b"",
            ciphersuite.aead_key_length(),
        )?;
        Ok(AeadKey::from_secret(aead_secret, ciphersuite))
    }

    /// Derive a new AEAD nonce from a `WelcomeSecret`.
    fn derive_aead_nonce(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<AeadNonce, CryptoError> {
        let nonce_secret = self.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "nonce",
            b"",
            ciphersuite.aead_nonce_length(),
        )?;
        Ok(AeadNonce::from_secret(nonce_secret))
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// An intermediate secret in the key schedule, the `EpochSecret` is used to
/// create an `EpochSecrets` object and is finally consumed when creating that
/// epoch's `InitSecret`.
struct EpochSecret {
    secret: Secret,
}

impl EpochSecret {
    /// Derive an `EpochSecret` from a `JoinerSecret`
    fn new(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        intermediate_secret: IntermediateSecret,
        serialized_group_context: &[u8],
    ) -> Result<Self, CryptoError> {
        let secret = intermediate_secret.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "epoch",
            serialized_group_context,
            ciphersuite.hash_length(),
        )?;
        log_crypto!(trace, "Epoch secret: {:x?}", secret);
        Ok(EpochSecret { secret })
    }
}

/// The `EncryptionSecret` is used to create a `SecretTree`.
#[cfg_attr(test, derive(Clone))]
pub(crate) struct EncryptionSecret {
    secret: Secret,
}

impl EncryptionSecret {
    /// Derive an encryption secret from a reference to an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        Ok(EncryptionSecret {
            secret: epoch_secret
                .secret
                .derive_secret(crypto, ciphersuite, "encryption")?,
        })
    }

    /// Create a `SecretTree` from the `encryption_secret` contained in the
    /// `EpochSecrets`. The `encryption_secret` is consumed, allowing us to achieve FS.
    pub(crate) fn create_secret_tree(
        self,
        treesize: TreeSize,
        own_index: LeafNodeIndex,
    ) -> SecretTree {
        SecretTree::new(self, treesize, own_index)
    }

    pub(crate) fn consume_secret(self) -> Secret {
        self.secret
    }

    /// Create a random `EncryptionSecret`. For testing purposes only.
    #[cfg(test)]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        EncryptionSecret {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self {
            secret: Secret::from_slice(bytes),
        }
    }
}

/// A secret that we can derive secrets from, that are used outside of OpenMLS.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct ExporterSecret {
    secret: Secret,
}

impl ExporterSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "exporter")?;
        Ok(ExporterSecret { secret })
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    /// Derive a `Secret` from the exporter secret. We return `Vec<u8>` here, so
    /// it can be used outside of OpenMLS. This function is made available for
    /// use from the outside through [`MlsGroup::export_secret`].
    pub(crate) fn derive_exported_secret(
        &self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let context_hash = &crypto.hash(ciphersuite.hash_algorithm(), context)?;
        Ok(self
            .secret
            .derive_secret(crypto, ciphersuite, label)?
            .kdf_expand_label(crypto, ciphersuite, "exported", context_hash, key_length)?
            .as_slice()
            .to_vec())
    }
}

/// A secret used when joining a group with an external Commit.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct ExternalSecret {
    secret: Secret,
}

impl ExternalSecret {
    /// Derive an `ExternalSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "external")?;
        Ok(Self { secret })
    }

    /// Derive the external keypair for External Commits
    pub(crate) fn derive_external_keypair(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<HpkeKeyPair, CryptoError> {
        crypto.derive_hpke_keypair(ciphersuite.hpke_config(), self.secret.as_slice())
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// The confirmation key is used to calculate the `ConfirmationTag`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct ConfirmationKey {
    secret: Secret,
}

impl ConfirmationKey {
    /// Derive an `ConfirmationKey` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        log::debug!("Computing confirmation key.");
        log_crypto!(
            trace,
            "  epoch_secret {:x?}",
            epoch_secret.secret.as_slice()
        );
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "confirm")?;
        Ok(Self { secret })
    }

    /// Create a new confirmation tag.
    ///
    /// >  11.2. Commit
    ///
    /// ```text
    /// PublicMessage.confirmation_tag =
    ///     MAC(confirmation_key, GroupContext.confirmed_transcript_hash)
    /// ```
    pub(crate) fn tag(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        confirmed_transcript_hash: &[u8],
    ) -> Result<ConfirmationTag, CryptoError> {
        log::debug!("Computing confirmation tag.");
        log_crypto!(trace, "  confirmation key {:x?}", self.secret.as_slice());
        log_crypto!(trace, "  transcript hash  {:x?}", confirmed_transcript_hash);
        Ok(ConfirmationTag(Mac::new(
            crypto,
            ciphersuite,
            &self.secret,
            confirmed_transcript_hash,
        )?))
    }
}

#[cfg(test)]
impl ConfirmationKey {
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self { secret }
    }
}

#[cfg(any(feature = "test-utils", test))]
impl ConfirmationKey {
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// The membership key is used to calculate the `MembershipTag`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(PartialEq, Clone))]
pub(crate) struct MembershipKey {
    secret: Secret,
}

impl MembershipKey {
    /// Derive an `MembershipKey` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "membership")?;
        Ok(Self { secret })
    }

    /// Create a new membership tag.
    ///
    /// 9.1 Content Authentication
    ///
    /// ```text
    /// membership_tag = MAC(membership_key, MLSPlaintextTBM);
    /// ```
    pub(crate) fn tag_message(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        tbm_payload: AuthenticatedContentTbm,
    ) -> Result<MembershipTag, LibraryError> {
        Ok(MembershipTag(
            Mac::new(
                crypto,
                ciphersuite,
                &self.secret,
                &tbm_payload
                    .into_bytes()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .map_err(LibraryError::unexpected_crypto_error)?,
        ))
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self { secret }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }
}

// Get a ciphertext sample of `hash_length` from the ciphertext.
fn ciphertext_sample(ciphersuite: Ciphersuite, ciphertext: &[u8]) -> &[u8] {
    let sample_length = ciphersuite.hash_length();
    log::debug!("Getting ciphertext sample of length {:?}", sample_length);
    if ciphertext.len() <= sample_length {
        ciphertext
    } else {
        &ciphertext[0..sample_length]
    }
}

/// A key that can be used to derive an `AeadKey` and an `AeadNonce`.
#[derive(Serialize, Deserialize)]
#[cfg_attr(
    any(feature = "test-utils", feature = "crypto-debug", test),
    derive(Debug, Clone, PartialEq)
)]
pub(crate) struct SenderDataSecret {
    secret: Secret,
}

impl SenderDataSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: &EpochSecret,
    ) -> Result<Self, CryptoError> {
        let secret = epoch_secret
            .secret
            .derive_secret(crypto, ciphersuite, "sender data")?;
        Ok(SenderDataSecret { secret })
    }

    /// Derive a new AEAD key from a `SenderDataSecret`.
    pub(crate) fn derive_aead_key(
        &self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        ciphertext: &[u8],
    ) -> Result<AeadKey, CryptoError> {
        let ciphertext_sample = ciphertext_sample(ciphersuite, ciphertext);
        log::debug!(
            "SenderDataSecret::derive_aead_key ciphertext sample: {:x?}",
            ciphertext_sample
        );
        let secret = self.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "key",
            ciphertext_sample,
            ciphersuite.aead_key_length(),
        )?;
        Ok(AeadKey::from_secret(secret, ciphersuite))
    }

    /// Derive a new AEAD nonce from a `SenderDataSecret`.
    pub(crate) fn derive_aead_nonce(
        &self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        ciphertext: &[u8],
    ) -> Result<AeadNonce, CryptoError> {
        let ciphertext_sample = ciphertext_sample(ciphersuite, ciphertext);
        log::debug!(
            "SenderDataSecret::derive_aead_nonce ciphertext sample: {:x?}",
            ciphertext_sample
        );
        let nonce_secret = self.secret.kdf_expand_label(
            crypto,
            ciphersuite,
            "nonce",
            ciphertext_sample,
            ciphersuite.aead_nonce_length(),
        )?;
        Ok(AeadNonce::from_secret(nonce_secret))
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: Ciphersuite, rng: &impl OpenMlsRand) -> Self {
        Self {
            secret: Secret::random(ciphersuite, rng).expect("Not enough randomness."),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self {
            secret: Secret::from_slice(bytes),
        }
    }
}

/// The `EpochSecrets` contain keys (or secrets), which are accessible outside
/// of the `KeySchedule` and which don't get consumed immediately upon first
/// use.
///
/// | Secret                  | Label           |
/// |:------------------------|:----------------|
/// | `init_secret`           | "init"          |
/// | `sender_data_secret`    | "sender data"   |
/// | `encryption_secret`     | "encryption"    |
/// | `exporter_secret`       | "exporter"      |
/// | `epoch_authenticator`   | "authentication"|
/// | `external_secret`       | "external"      |
/// | `confirmation_key`      | "confirm"       |
/// | `membership_key`        | "membership"    |
/// | `resumption_psk`        | "resumption"    |
pub(crate) struct EpochSecrets {
    init_secret: InitSecret,
    sender_data_secret: SenderDataSecret,
    encryption_secret: EncryptionSecret,
    exporter_secret: ExporterSecret,
    epoch_authenticator: EpochAuthenticator,
    external_secret: ExternalSecret,
    confirmation_key: ConfirmationKey,
    membership_key: MembershipKey,
    resumption_psk: ResumptionPskSecret,
}

impl std::fmt::Debug for EpochSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochSecrets { *** }")
    }
}

#[cfg(not(test))]
impl PartialEq for EpochSecrets {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

// In tests we allow comparing secrets.
#[cfg(test)]
impl PartialEq for EpochSecrets {
    fn eq(&self, other: &Self) -> bool {
        self.sender_data_secret == other.sender_data_secret
            && self.exporter_secret == other.exporter_secret
            && self.epoch_authenticator == other.epoch_authenticator
            && self.external_secret == other.external_secret
            && self.confirmation_key == other.confirmation_key
            && self.membership_key == other.membership_key
            && self.resumption_psk == other.resumption_psk
    }
}

impl EpochSecrets {
    /// Get the sender_data secret.
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    /// Get the confirmation key.
    pub(crate) fn confirmation_key(&self) -> &ConfirmationKey {
        &self.confirmation_key
    }

    /// Epoch authenticator
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn epoch_authenticator(&self) -> &EpochAuthenticator {
        &self.epoch_authenticator
    }

    /// Exporter secret
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn exporter_secret(&self) -> &ExporterSecret {
        &self.exporter_secret
    }

    /// Membership key
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn membership_key(&self) -> &MembershipKey {
        &self.membership_key
    }

    /// External secret
    pub(crate) fn external_secret(&self) -> &ExternalSecret {
        &self.external_secret
    }

    /// External secret
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn resumption_psk(&self) -> &ResumptionPskSecret {
        &self.resumption_psk
    }

    /// Init secret
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn init_secret(&self) -> &InitSecret {
        &self.init_secret
    }

    /// Encryption secret
    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn encryption_secret(&self) -> &EncryptionSecret {
        &self.encryption_secret
    }

    /// Derive `EpochSecrets` from an `EpochSecret`.
    /// If the `with_init_secret` argument is `true`, the init secret is derived and
    /// part of the `EpochSecrets`. Otherwise not.
    fn new(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        epoch_secret: EpochSecret,
    ) -> Result<Self, CryptoError> {
        log::debug!(
            "Computing EpochSecrets from epoch secret with {}",
            ciphersuite
        );
        log_crypto!(
            trace,
            "  epoch_secret: {:x?}",
            epoch_secret.secret.as_slice()
        );
        let sender_data_secret = SenderDataSecret::new(crypto, ciphersuite, &epoch_secret)?;
        let encryption_secret = EncryptionSecret::new(crypto, ciphersuite, &epoch_secret)?;
        let exporter_secret = ExporterSecret::new(crypto, ciphersuite, &epoch_secret)?;
        let epoch_authenticator = EpochAuthenticator::new(crypto, ciphersuite, &epoch_secret)?;
        let external_secret = ExternalSecret::new(crypto, ciphersuite, &epoch_secret)?;
        let confirmation_key = ConfirmationKey::new(crypto, ciphersuite, &epoch_secret)?;
        let membership_key = MembershipKey::new(crypto, ciphersuite, &epoch_secret)?;
        let resumption_psk = ResumptionPskSecret::new(crypto, ciphersuite, &epoch_secret)?;

        log::trace!("  Computing init secret.");
        let init_secret = InitSecret::new(crypto, ciphersuite, epoch_secret)?;

        Ok(EpochSecrets {
            init_secret,
            sender_data_secret,
            encryption_secret,
            exporter_secret,
            epoch_authenticator,
            external_secret,
            confirmation_key,
            membership_key,
            resumption_psk,
        })
    }

    /// This function initializes the `EpochSecrets` from an all-zero
    /// epoch-secret with the exception of the `init_secret`, which is populated
    /// with the given `InitSecret`. This is meant to be used in the case of an
    /// external init.
    pub(crate) fn with_init_secret(
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
        init_secret: InitSecret,
    ) -> Result<Self, CryptoError> {
        let epoch_secret = EpochSecret {
            secret: Secret::zero(ciphersuite),
        };
        let mut epoch_secrets = Self::new(crypto, ciphersuite, epoch_secret)?;
        epoch_secrets.init_secret = init_secret;
        Ok(epoch_secrets)
    }

    /// Splits `EpochSecrets` into two different categories:
    ///  - [`GroupEpochSecrets`]: These secrets are only used within the same epoch
    ///  - [`MessageSecrets`]: These secrets are potentially also used for past epochs
    ///    to decrypt and validate messages
    pub(crate) fn split_secrets(
        self,
        serialized_context: Vec<u8>,
        treesize: TreeSize,
        own_index: LeafNodeIndex,
    ) -> (GroupEpochSecrets, MessageSecrets) {
        let secret_tree = self
            .encryption_secret
            .create_secret_tree(treesize, own_index);
        (
            GroupEpochSecrets {
                init_secret: self.init_secret,
                exporter_secret: self.exporter_secret,
                epoch_authenticator: self.epoch_authenticator,
                external_secret: self.external_secret,
                resumption_psk: self.resumption_psk,
            },
            MessageSecrets::new(
                self.sender_data_secret,
                self.membership_key,
                self.confirmation_key,
                serialized_context,
                secret_tree,
            ),
        )
    }
}

#[derive(Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub(crate) struct GroupEpochSecrets {
    init_secret: InitSecret,
    exporter_secret: ExporterSecret,
    epoch_authenticator: EpochAuthenticator,
    external_secret: ExternalSecret,
    resumption_psk: ResumptionPskSecret,
}

impl std::fmt::Debug for GroupEpochSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GroupEpochSecrets { *** }")
    }
}

#[cfg(not(any(test, feature = "test-utils")))]
impl PartialEq for GroupEpochSecrets {
    fn eq(&self, _other: &Self) -> bool {
        false
    }
}

impl GroupEpochSecrets {
    /// Init secret
    pub(crate) fn init_secret(&self) -> &InitSecret {
        &self.init_secret
    }

    /// Epoch authenticator
    pub(crate) fn epoch_authenticator(&self) -> &EpochAuthenticator {
        &self.epoch_authenticator
    }

    /// Exporter secret
    pub(crate) fn exporter_secret(&self) -> &ExporterSecret {
        &self.exporter_secret
    }

    /// External secret
    pub(crate) fn external_secret(&self) -> &ExternalSecret {
        &self.external_secret
    }

    /// External secret
    pub(crate) fn resumption_psk(&self) -> &ResumptionPskSecret {
        &self.resumption_psk
    }
}
