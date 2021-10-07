//! This module represents the key schedule as introduced in Section 8 of the
//! MLS specification. The key schedule evolves in epochs, where in each epoch
//! new key material is injected.
//!
//! The flow of the key schedule is as follows (from Section 8 of the MLS
//! specification):
//!
//! ```text
//!                  init_secret_[n-1]
//!                         |
//!                         V
//!    commit_secret -> KDF.Extract
//!                         |
//!                         V
//!                   DeriveSecret(., "joiner")
//!                         |
//!                         V
//!                    joiner_secret
//!                         |
//!                         V
//! psk_secret (or 0) -> KDF.Extract (= intermediary_secret)
//!                         |
//!                         +--> DeriveSecret(., "welcome")
//!                         |    = welcome_secret
//!                         |
//!                         V
//!                   ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//!                         |
//!                         V
//!                    epoch_secret
//!                         |
//!                         +--> DeriveSecret(., <label>)
//!                         |    = <secret>
//!                         |
//!                         V
//!                   DeriveSecret(., "init")
//!                         |
//!                         V
//!                   init_secret_[n]
//! ```
//!
//! Each of the secrets in the key schedule (with exception of the
//! welcome_secret) is represented by its own struct to ensure that the keys are
//! not confused with one-another and/or that the schedule is not derived
//! out-of-order.
//!
//! ## The real key schedules
//! The key schedule as described in the spec isn't really one key schedule.
//! The `joiner_secret` is an intermediate value *and* an output value. This
//! must never be the case within a key schedule. The actual key schedule is
//! therefore only the second half starting with the `joiner_secret`, which
//! indeed is what happens when starting a group from a welcome message.
//!
//! The `joiner_secret` is computed as
//!
//! ```text
//!     DeriveSecret(KDF.Extract(init_secret_[n-1], commit_secret), "joiner")
//! ```
//!
//! or
//!
//! ```text
//!                  init_secret_[n-1]
//!                         |
//!                         V
//!    commit_secret -> KDF.Extract
//!                         |
//!                         V
//!                   DeriveSecret(., "joiner")
//!                         |
//!                         V
//!                    joiner_secret
//! ```
//!
//! The remainder of the key schedule then starts with the `joiner_secret` and
//! `psk_secret`. Note that the following graph also adds the `GroupContext_[n]`
//! as input, which is omitted in the spec.
//! Further note that the derivation of the secrets from the `epoch_secret` is
//! simplified here.
//!
//! ```text
//!                    joiner_secret
//!                         |
//!                         V
//! psk_secret (or 0) -> KDF.Extract
//!                         |
//!                         +--> DeriveSecret(., "welcome")
//!                         |    = welcome_secret
//!                         |
//!                         V
//! GroupContext_[n] -> ExpandWithLabel(., "epoch", GroupContext_[n], KDF.Nh)
//!                         |
//!                         V
//!                    epoch_secret
//!                         |
//!                         v
//!                 DeriveSecret(., <label>)
//!                     = <secret>
//! ```
//!
//! with
//!
//! ```text
//! | secret                  | label           |
//! |:------------------------|:----------------|
//! | `init_secret`           | "init"          |
//! | `sender_data_secret`    | "sender data"   |
//! | `encryption_secret`     | "encryption"    |
//! | `exporter_secret`       | "exporter"      |
//! | `authentication_secret` | "authentication"|
//! | `external_secret`       | "external"      |
//! | `confirmation_key`      | "confirm"       |
//! | `membership_key`        | "membership"    |
//! | `resumption_secret`     | "resumption"    |
//! ```

use crate::framing::MlsPlaintextTbmPayload;
use crate::tree::index::LeafIndex;
use crate::tree::secret_tree::SecretTree;
use crate::{ciphersuite::Mac, group::GroupContext, prelude::MembershipTag};
use crate::{
    ciphersuite::{AeadKey, AeadNonce, Ciphersuite, HpkeKeyPair, Secret},
    config::ProtocolVersion,
    messages::ConfirmationTag,
};

use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use tls_codec::{Serialize as TlsSerializeTrait, Size, TlsDeserialize, TlsSerialize, TlsSize};

pub mod codec;
pub mod errors;
pub(crate) mod psk;

#[cfg(any(feature = "test-utils", test))]
pub mod kat_key_schedule;

pub use errors::{ErrorState, KeyScheduleError, PskSecretError};
pub use psk::{PreSharedKeyId, PreSharedKeys, PskSecret};

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct CommitSecret {
    secret: Secret,
}

impl Default for CommitSecret {
    fn default() -> Self {
        CommitSecret {
            secret: Secret::default(),
        }
    }
}

impl CommitSecret {
    pub(crate) fn new(ciphersuite: &Ciphersuite, path_secret: &Secret) -> Self {
        // FIXME: remove unwrap
        let secret = path_secret
            .kdf_expand_label("path", &[], ciphersuite.hash_length())
            .unwrap();

        Self { secret }
    }

    /// Create a CommitSecret consisting of an all-zero string of length
    /// `hash_length`.
    pub(crate) fn zero_secret(ciphersuite: &'static Ciphersuite, version: ProtocolVersion) -> Self {
        CommitSecret {
            secret: Secret::zero(ciphersuite, version),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: &'static Ciphersuite) -> Self {
        Self {
            secret: Secret::random(ciphersuite, None /* MLS version */),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn from_slice(b: &[u8]) -> Self {
        Self { secret: b.into() }
    }
}

/// The `InitSecret` is used to connect the next epoch to the current one.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct InitSecret {
    secret: Secret,
}

impl InitSecret {
    /// Derive an `InitSecret` from an `EpochSecret`.
    fn new(epoch_secret: EpochSecret) -> Self {
        // FIXME: remove unwrap
        let secret = epoch_secret.secret.derive_secret("init").unwrap();
        log_crypto!(trace, "Init secret: {:x?}", secret);
        InitSecret { secret }
    }

    /// Sample a fresh, random `InitSecret` for the creation of a new group.
    pub(crate) fn random(ciphersuite: &'static Ciphersuite, version: ProtocolVersion) -> Self {
        InitSecret {
            secret: Secret::random(ciphersuite, version),
        }
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

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn from_slice(b: &[u8]) -> Self {
        Self { secret: b.into() }
    }
}

#[derive(TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct JoinerSecret {
    secret: Secret,
}

impl JoinerSecret {
    /// Derive a `JoinerSecret` from an optional `CommitSecret` and an
    /// `EpochSecrets` object, which contains the necessary `InitSecret`. The
    /// `CommitSecret` needs to be present if the current commit is not a
    /// partial commit. TODO: For now, this takes a reference to a
    /// `CommitSecret` as input. This should change with #224.
    pub(crate) fn new<'a>(
        commit_secret_option: impl Into<Option<&'a CommitSecret>>,
        init_secret: &InitSecret,
    ) -> Self {
        let intermediate_secret = init_secret
            .secret
            .hkdf_extract(commit_secret_option.into().map(|cs| &cs.secret));
        // FIXME: remove unwrap
        let secret = intermediate_secret.derive_secret("joiner").unwrap();
        log_crypto!(trace, "Joiner secret: {:x?}", secret);
        JoinerSecret { secret }
    }

    /// Set the config for the secret, i.e. cipher suite and MLS version.
    pub(crate) fn config(
        &mut self,
        ciphersuite: &'static Ciphersuite,
        mls_version: ProtocolVersion,
    ) {
        self.secret.config(ciphersuite, mls_version);
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

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn random(ciphersuite: &'static Ciphersuite, version: ProtocolVersion) -> Self {
        Self {
            secret: Secret::random(ciphersuite, version),
        }
    }
}

#[derive(Debug, PartialEq)]
enum State {
    Initial,
    Context,
    Done,
}

pub(crate) struct KeySchedule {
    ciphersuite: &'static Ciphersuite,
    intermediate_secret: Option<IntermediateSecret>,
    epoch_secret: Option<EpochSecret>,
    state: State,
}

impl KeySchedule {
    /// Initialize the key schedule and return it.
    pub(crate) fn init(
        ciphersuite: &'static Ciphersuite,
        joiner_secret: JoinerSecret,
        psk: impl Into<Option<PskSecret>>,
    ) -> Self {
        log::debug!(
            "Initializing the key schedule with {:?} ...",
            ciphersuite.name()
        );
        log_crypto!(
            trace,
            "  joiner_secret: {:x?}",
            joiner_secret.secret.as_slice()
        );
        let psk = psk.into();
        log_crypto!(trace, "  {}", if psk.is_some() { "with PSK" } else { "" });
        let intermediate_secret = IntermediateSecret::new(&joiner_secret, psk);
        Self {
            ciphersuite,
            intermediate_secret: Some(intermediate_secret),
            epoch_secret: None,
            state: State::Initial,
        }
    }

    /// Derive the welcome secret.
    /// Note that this has to be called before the context is added.
    pub(crate) fn welcome(&self) -> Result<WelcomeSecret, KeyScheduleError> {
        if self.state != State::Initial || self.intermediate_secret.is_none() {
            log::error!("Trying to derive a welcome secret while not in the initial state.");
            return Err(KeyScheduleError::InvalidState(ErrorState::NotInit));
        }

        Ok(WelcomeSecret::new(
            self.intermediate_secret.as_ref().unwrap(),
        ))
    }

    /// Add the group context to the key schedule.
    pub(crate) fn add_context(
        &mut self,
        group_context: &GroupContext,
    ) -> Result<(), KeyScheduleError> {
        log::trace!("Adding context to key schedule. {:?}", group_context);
        if self.state != State::Initial || self.intermediate_secret.is_none() {
            log::error!(
                "Trying to add context to the key schedule while not in the initial state."
            );
            return Err(KeyScheduleError::InvalidState(ErrorState::NotInit));
        }
        self.state = State::Context;
        log_crypto!(
            trace,
            "  intermediate_secret: {:x?}",
            self.intermediate_secret.as_ref().unwrap().secret.as_slice()
        );

        self.epoch_secret = Some(EpochSecret::new(
            self.ciphersuite,
            self.intermediate_secret.take().unwrap(),
            group_context,
        ));
        self.intermediate_secret = None;
        Ok(())
    }

    /// Derive the epoch secrets.
    /// If the `init_secret` argument is `true`, the init secret is derived and
    /// part of the `EpochSecrets`. Otherwise not.
    pub(crate) fn epoch_secrets(
        &mut self,
        init_secret: bool,
    ) -> Result<EpochSecrets, KeyScheduleError> {
        if self.state != State::Context || self.epoch_secret.is_none() {
            log::error!("Trying to derive the epoch secrets while not in the right state.");
            return Err(KeyScheduleError::InvalidState(ErrorState::NotContext));
        }
        self.state = State::Done;

        Ok(EpochSecrets::new(
            self.epoch_secret.take().unwrap(),
            init_secret,
        ))
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
    fn new(joiner_secret: &JoinerSecret, psk: Option<PskSecret>) -> Self {
        log_crypto!(trace, "PSK input: {:x?}", psk.as_ref().map(|p| p.secret()));
        let secret = joiner_secret
            .secret
            .hkdf_extract(psk.as_ref().map(|p| p.secret()));
        log_crypto!(trace, "Intermediate secret: {:x?}", secret);
        Self { secret }
    }
}

pub(crate) struct WelcomeSecret {
    secret: Secret,
}

impl WelcomeSecret {
    /// Derive a `WelcomeSecret` from to decrypt a `Welcome` message.
    fn new(intermediate_secret: &IntermediateSecret) -> Self {
        // FIXME: remove unwrap
        let secret = intermediate_secret.secret.derive_secret("welcome").unwrap();
        log_crypto!(trace, "Welcome secret: {:x?}", secret);
        WelcomeSecret { secret }
    }

    /// Derive an `AeadKey` and an `AeadNonce` from the `WelcomeSecret`,
    /// consuming it in the process.
    pub(crate) fn derive_welcome_key_nonce(self) -> (AeadKey, AeadNonce) {
        let welcome_nonce = self.derive_aead_nonce();
        let welcome_key = self.derive_aead_key();
        (welcome_key, welcome_nonce)
    }

    /// Derive a new AEAD key from a `WelcomeSecret`.
    fn derive_aead_key(&self) -> AeadKey {
        log::trace!(
            "WelcomeSecret.derive_aead_key with {}",
            self.secret.ciphersuite()
        );
        let aead_secret = self
            .secret
            .hkdf_expand(b"key", self.secret.ciphersuite().aead_key_length())
            .unwrap();
        AeadKey::from_secret(aead_secret)
    }

    /// Derive a new AEAD nonce from a `WelcomeSecret`.
    fn derive_aead_nonce(&self) -> AeadNonce {
        let nonce_secret = self
            .secret
            .hkdf_expand(b"nonce", self.secret.ciphersuite().aead_nonce_length())
            .unwrap();
        AeadNonce::from_secret(nonce_secret)
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
        ciphersuite: &Ciphersuite,
        intermediate_secret: IntermediateSecret,
        group_context: &GroupContext,
    ) -> Self {
        // FIXME: remove unwraps
        let secret = intermediate_secret
            .secret
            .kdf_expand_label(
                "epoch",
                &group_context.tls_serialize_detached().unwrap(),
                ciphersuite.hash_length(),
            )
            .unwrap();
        log_crypto!(trace, "Epoch secret: {:x?}", secret);
        EpochSecret { secret }
    }
}

/// The `EncryptionSecret` is used to create a `SecretTree`.
#[derive(Serialize, Deserialize, Default)] // FIXME: what do we want serialization do here?
pub(crate) struct EncryptionSecret {
    secret: Secret,
}

impl EncryptionSecret {
    /// Derive an encryption secret from a reference to an `EpochSecret`.
    fn new(epoch_secret: &EpochSecret) -> Self {
        // FIXME: remove unwrap
        EncryptionSecret {
            secret: epoch_secret.secret.derive_secret("encryption").unwrap(),
        }
    }

    /// Create a `SecretTree` from the `encryption_secret` contained in the
    /// `EpochSecrets`. The `encryption_secret` is replaced with `None` in the
    /// process, allowing us to achieve FS.
    pub(crate) fn create_secret_tree(self, treesize: LeafIndex) -> SecretTree {
        SecretTree::new(self, treesize)
    }

    pub(crate) fn consume_secret(self) -> Secret {
        self.secret
    }

    /// Create a random `EncryptionSecret`. For testing purposes only.
    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) fn random(ciphersuite: &'static Ciphersuite) -> Self {
        EncryptionSecret {
            secret: Secret::random(ciphersuite, None /* MLS version */),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    #[doc(hidden)]
    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(
        bytes: &[u8],
        mls_version: ProtocolVersion,
        ciphersuite: &'static Ciphersuite,
    ) -> Self {
        Self {
            secret: Secret::from_slice(bytes, mls_version, ciphersuite),
        }
    }
}

/// A secret that we can derive secrets from, that are used outside of OpenMLS.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ExporterSecret {
    secret: Secret,
}

impl ExporterSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    fn new(epoch_secret: &EpochSecret) -> Self {
        // FIXME: remove unwrap
        let secret = epoch_secret.secret.derive_secret("exporter").unwrap();
        ExporterSecret { secret }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    /// Derive a `Secret` from the exporter secret. We return `Vec<u8>` here, so
    /// it can be used outside of OpenMLS. This function is made available for
    /// use from the outside through [`crate::group::mls_group::export_secret`].
    pub(crate) fn derive_exported_secret(
        &self,
        ciphersuite: &Ciphersuite,
        label: &str,
        context: &[u8],
        key_length: usize,
    ) -> Vec<u8> {
        let context_hash = &ciphersuite.hash(context);
        // FIXME: remove unwraps
        self.secret
            .derive_secret(label)
            .unwrap()
            .kdf_expand_label(label, context_hash, key_length)
            .unwrap()
            .as_slice()
            .to_vec()
    }
}

/// A secret that can be used among members to make sure everyone has the same
/// group state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct AuthenticationSecret {
    secret: Secret,
}

impl AuthenticationSecret {
    /// Derive an `AuthenticationSecret` from an `EpochSecret`.
    fn new(epoch_secret: &EpochSecret) -> Self {
        // FIXME: remove unwrap
        let secret = epoch_secret.secret.derive_secret("authentication").unwrap();
        Self { secret }
    }

    /// ☣️ Get a copy of the secret bytes.
    pub(crate) fn export(&self) -> Vec<u8> {
        self.secret.as_slice().to_vec()
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// A secret used when joining a group with an external Commit.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ExternalSecret {
    secret: Secret,
}

impl ExternalSecret {
    /// Derive an `ExternalSecret` from an `EpochSecret`.
    fn new(epoch_secret: &EpochSecret) -> Self {
        // FIXME: remove unwrap
        let secret = epoch_secret.secret.derive_secret("external").unwrap();
        Self { secret }
    }

    /// Derive the external keypair for External Commits
    pub(crate) fn derive_external_keypair(&self, ciphersuite: &Ciphersuite) -> HpkeKeyPair {
        ciphersuite.derive_hpke_keypair(&self.secret)
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// The confirmation key is used to calculate the `ConfirmationTag`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ConfirmationKey {
    secret: Secret,
}

impl ConfirmationKey {
    /// Derive an `ConfirmationKey` from an `EpochSecret`.
    fn new(epoch_secret: &EpochSecret) -> Self {
        log::debug!("Computing confirmation key.");
        log_crypto!(
            trace,
            "  epoch_secret {:x?}",
            epoch_secret.secret.as_slice()
        );
        // FIXME: remove unwrap
        let secret = epoch_secret.secret.derive_secret("confirm").unwrap();
        Self { secret }
    }

    /// Create a new confirmation tag.
    ///
    /// >  11.2. Commit
    ///
    /// ```text
    /// MLSPlaintext.confirmation_tag =
    ///     MAC(confirmation_key, GroupContext.confirmed_transcript_hash)
    /// ```
    pub fn tag(&self, confirmed_transcript_hash: &[u8]) -> ConfirmationTag {
        log::debug!("Computing confirmation tag.");
        log_crypto!(trace, "  confirmation key {:x?}", self.secret.as_slice());
        log_crypto!(trace, "  transcript hash  {:x?}", confirmed_transcript_hash);
        ConfirmationTag(Mac::new(&self.secret, confirmed_transcript_hash))
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self { secret }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// The membership key is used to calculate the `MembershipTag`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MembershipKey {
    secret: Secret,
}

impl MembershipKey {
    /// Derive an `MembershipKey` from an `EpochSecret`.
    fn new(epoch_secret: &EpochSecret) -> Self {
        // FIXME: remove unwrap
        let secret = epoch_secret.secret.derive_secret("membership").unwrap();
        Self { secret }
    }

    /// Create a new membership tag.
    ///
    /// 9.1 Content Authentication
    ///
    /// ```text
    /// membership_tag = MAC(membership_key, MLSPlaintextTBM);
    /// ```
    pub(crate) fn tag(
        &self,
        tbm_payload: MlsPlaintextTbmPayload,
    ) -> Result<MembershipTag, tls_codec::Error> {
        Ok(MembershipTag(Mac::new(
            &self.secret,
            &tbm_payload.into_bytes()?,
        )))
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self { secret }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

/// A secret used in cross-group operations.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ResumptionSecret {
    secret: Secret,
}

impl ResumptionSecret {
    /// Derive an `ResumptionSecret` from an `EpochSecret`.
    fn new(epoch_secret: &EpochSecret) -> Self {
        // FIXME: remove unwrap
        let secret = epoch_secret.secret.derive_secret("resumption").unwrap();
        Self { secret }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }
}

// Get a ciphertext sample of `hash_length` from the ciphertext.
fn ciphertext_sample<'a>(ciphersuite: &Ciphersuite, ciphertext: &'a [u8]) -> &'a [u8] {
    let sample_length = ciphersuite.hash_length();
    log::debug!("Getting ciphertext sample of length {:?}", sample_length);
    if ciphertext.len() <= sample_length {
        ciphertext
    } else {
        &ciphertext[0..sample_length]
    }
}

/// A key that can be used to derive an `AeadKey` and an `AeadNonce`.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct SenderDataSecret {
    secret: Secret,
}

impl SenderDataSecret {
    /// Derive an `ExporterSecret` from an `EpochSecret`.
    fn new(epoch_secret: &EpochSecret) -> Self {
        // FIXME: remove unwrap
        let secret = epoch_secret.secret.derive_secret("sender data").unwrap();
        SenderDataSecret { secret }
    }

    /// Derive a new AEAD key from a `SenderDataSecret`.
    pub(crate) fn derive_aead_key(&self, ciphertext: &[u8]) -> AeadKey {
        let ciphertext_sample = ciphertext_sample(self.secret.ciphersuite(), ciphertext);
        log::debug!(
            "SenderDataSecret::derive_aead_key ciphertext sample: {:x?}",
            ciphertext_sample
        );
        // FIXME: remove unwrap
        let secret = self
            .secret
            .kdf_expand_label(
                "key",
                ciphertext_sample,
                self.secret.ciphersuite().aead_key_length(),
            )
            .unwrap();
        AeadKey::from_secret(secret)
    }

    /// Derive a new AEAD nonce from a `SenderDataSecret`.
    pub(crate) fn derive_aead_nonce(
        &self,
        ciphersuite: &Ciphersuite,
        ciphertext: &[u8],
    ) -> AeadNonce {
        let ciphertext_sample = ciphertext_sample(ciphersuite, ciphertext);
        log::debug!(
            "SenderDataSecret::derive_aead_nonce ciphertext sample: {:x?}",
            ciphertext_sample
        );
        // FIXME: remove unwrap
        let nonce_secret = self
            .secret
            .kdf_expand_label("nonce", ciphertext_sample, ciphersuite.aead_nonce_length())
            .unwrap();
        AeadNonce::from_secret(nonce_secret)
    }

    #[cfg(any(feature = "test-utils", test))]
    #[doc(hidden)]
    pub fn random(ciphersuite: &'static Ciphersuite) -> Self {
        Self {
            secret: Secret::random(ciphersuite, None /* MLS version */),
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.as_slice()
    }

    #[cfg(any(feature = "test-utils", test))]
    #[doc(hidden)]
    /// Create a new secret from a byte vector.
    pub(crate) fn from_slice(
        bytes: &[u8],
        mls_version: ProtocolVersion,
        ciphersuite: &'static Ciphersuite,
    ) -> Self {
        Self {
            secret: Secret::from_slice(bytes, mls_version, ciphersuite),
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
/// | `authentication_secret` | "authentication"|
/// | `external_secret`       | "external"      |
/// | `confirmation_key`      | "confirm"       |
/// | `membership_key`        | "membership"    |
/// | `resumption_secret`     | "resumption"    |
#[derive(Serialize, Deserialize)]
pub(crate) struct EpochSecrets {
    init_secret: Option<InitSecret>,
    sender_data_secret: SenderDataSecret,
    encryption_secret: RefCell<EncryptionSecret>,
    exporter_secret: ExporterSecret,
    authentication_secret: AuthenticationSecret,
    external_secret: ExternalSecret,
    confirmation_key: ConfirmationKey,
    membership_key: MembershipKey,
    resumption_secret: ResumptionSecret,
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
            && self.authentication_secret == other.authentication_secret
            && self.external_secret == other.external_secret
            && self.confirmation_key == other.confirmation_key
            && self.membership_key == other.membership_key
            && self.resumption_secret == other.resumption_secret
    }
}

impl EpochSecrets {
    /// Get the sender_data secret.
    pub(crate) fn sender_data_secret(&self) -> &SenderDataSecret {
        &self.sender_data_secret
    }

    /// Get the confirmation key.
    pub(crate) fn confirmation_key(&self) -> &ConfirmationKey {
        &self.confirmation_key
    }

    /// Authentication secret
    pub(crate) fn authentication_secret(&self) -> &AuthenticationSecret {
        &self.authentication_secret
    }

    /// Exporter secret
    pub(crate) fn exporter_secret(&self) -> &ExporterSecret {
        &self.exporter_secret
    }

    /// Membership key
    pub(crate) fn membership_key(&self) -> &MembershipKey {
        &self.membership_key
    }

    /// External secret
    pub(crate) fn external_secret(&self) -> &ExternalSecret {
        &self.external_secret
    }

    /// External secret
    pub(crate) fn resumption_secret(&self) -> &ResumptionSecret {
        &self.resumption_secret
    }

    /// Init secret
    pub(crate) fn init_secret(&self) -> Option<&InitSecret> {
        self.init_secret.as_ref()
    }

    /// Encryption secret
    /// Note that this consumes the encryption secret.
    pub(crate) fn encryption_secret(&self) -> EncryptionSecret {
        // Note that we need to use a `RefCell` and not a `Cell` here because
        // we don't want to implement `Copy` for secrets.
        self.encryption_secret.take()
    }

    /// Derive `EpochSecrets` from an `EpochSecret`.
    /// If the `init_secret` argument is `true`, the init secret is derived and
    /// part of the `EpochSecrets`. Otherwise not.
    fn new(epoch_secret: EpochSecret, init_secret: bool) -> Self {
        log::debug!(
            "Computing EpochSecrets from epoch secret with {}",
            epoch_secret.secret.ciphersuite()
        );
        log_crypto!(
            trace,
            "  epoch_secret: {:x?}",
            epoch_secret.secret.as_slice()
        );
        let sender_data_secret = SenderDataSecret::new(&epoch_secret);
        let encryption_secret = EncryptionSecret::new(&epoch_secret);
        let exporter_secret = ExporterSecret::new(&epoch_secret);
        let authentication_secret = AuthenticationSecret::new(&epoch_secret);
        let external_secret = ExternalSecret::new(&epoch_secret);
        let confirmation_key = ConfirmationKey::new(&epoch_secret);
        let membership_key = MembershipKey::new(&epoch_secret);
        let resumption_secret = ResumptionSecret::new(&epoch_secret);

        let init_secret = if init_secret {
            log::trace!("  Computing init secret.");
            Some(InitSecret::new(epoch_secret))
        } else {
            None
        };

        EpochSecrets {
            init_secret,
            sender_data_secret,
            encryption_secret: RefCell::new(encryption_secret),
            exporter_secret,
            authentication_secret,
            external_secret,
            confirmation_key,
            membership_key,
            resumption_secret,
        }
    }

    #[cfg(any(feature = "test-utils", test))]
    #[doc(hidden)]
    pub(crate) fn sender_data_secret_mut(&mut self) -> &mut SenderDataSecret {
        &mut self.sender_data_secret
    }
}
