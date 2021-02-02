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

use crate::ciphersuite::{AeadKey, AeadNonce, Ciphersuite, HPKEKeyPair, Secret};
use crate::codec::*;
use crate::group::GroupContext;
use crate::tree::index::LeafIndex;
use crate::tree::secret_tree::SecretTree;
use crate::utils::zero;

use serde::{Deserialize, Serialize};
use std::cell::RefCell;

pub mod codec;
pub mod errors;
pub(crate) mod psk;

#[cfg(test)]
mod kat_key_schedule;

use errors::{ErrorState, KeyScheduleError};

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
        let secret =
            path_secret.kdf_expand_label(ciphersuite, "path", &[], ciphersuite.hash_length());

        Self { secret }
    }

    fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Create a CommitSecret consisting of an all-zero string of length
    /// `hash_length`.
    pub(crate) fn zero_secret(ciphersuite: &Ciphersuite) -> Self {
        CommitSecret {
            secret: Secret::from(zero(ciphersuite.hash_length())),
        }
    }

    #[cfg(test)]
    pub(crate) fn random(length: usize) -> Self {
        Self {
            secret: Secret::random(length),
        }
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
    }

    #[cfg(test)]
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
    fn new(ciphersuite: &Ciphersuite, epoch_secret: EpochSecret) -> Self {
        InitSecret {
            secret: epoch_secret.secret.derive_secret(ciphersuite, "init"),
        }
    }

    /// Sample a fresh, random `InitSecret` for the creation of a new group.
    pub(crate) fn random(length: usize) -> Self {
        InitSecret {
            secret: Secret::random(length),
        }
    }

    #[cfg(test)]
    pub(crate) fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
    }

    #[cfg(test)]
    pub(crate) fn from_slice(b: &[u8]) -> Self {
        Self { secret: b.into() }
    }
}

pub(crate) struct JoinerSecret {
    secret: Secret,
}

impl JoinerSecret {
    /// Derive a `JoinerSecret` from an optional `CommitSecret` and an
    /// `EpochSecrets` object, which contains the necessary `InitSecret`. The
    /// `CommitSecret` needs to be present if the current commit is not an
    /// Add-only commit. TODO: For now, this takes a reference to a
    /// `CommitSecret` as input. This should change with #224.
    pub(crate) fn new<'a>(
        ciphersuite: &Ciphersuite,
        commit_secret_option: impl Into<Option<&'a CommitSecret>>,
        init_secret: &InitSecret,
    ) -> Self {
        let commit_secret_value = commit_secret_option
            .into()
            .map(|commit_secret| commit_secret.secret());
        let intermediate_secret =
            ciphersuite.hkdf_extract(commit_secret_value, &init_secret.secret);
        JoinerSecret {
            secret: intermediate_secret.derive_secret(ciphersuite, "joiner"),
        }
    }

    #[cfg(test)]
    pub(crate) fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
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
        psk: impl Into<Option<Secret>>,
    ) -> Self {
        let intermediate_secret = IntermediateSecret::new(ciphersuite, &joiner_secret, psk.into());
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
            self.ciphersuite,
            self.intermediate_secret.as_ref().unwrap(),
        ))
    }

    /// Add the group context to the key schedule.
    pub(crate) fn add_context(
        &mut self,
        group_context: &GroupContext,
    ) -> Result<(), KeyScheduleError> {
        if self.state != State::Initial || self.intermediate_secret.is_none() {
            log::error!(
                "Trying to add context to the key schedule while not in the initial state."
            );
            return Err(KeyScheduleError::InvalidState(ErrorState::NotInit));
        }
        self.state = State::Context;

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
            self.ciphersuite,
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
    /// Derive ans `IntermediateSecret` from a `JoinerSecret` and an optional
    /// PSK.
    fn new(ciphersuite: &Ciphersuite, joiner_secret: &JoinerSecret, psk: Option<Secret>) -> Self {
        Self {
            secret: ciphersuite.hkdf_extract(psk.as_ref(), &joiner_secret.secret),
        }
    }
}

pub(crate) struct WelcomeSecret {
    secret: Secret,
}

impl WelcomeSecret {
    /// Derive a `WelcomeSecret` from to decrypt a `Welcome` message.
    fn new(ciphersuite: &Ciphersuite, intermediate_secret: &IntermediateSecret) -> Self {
        // Unwrapping here is safe, because we know the key is not empty
        let secret = ciphersuite
            .hkdf_expand(
                &intermediate_secret.secret,
                b"welcome",
                ciphersuite.hash_length(),
            )
            .unwrap();
        WelcomeSecret { secret }
    }

    /// Get the `Secret` of the `WelcomeSecret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    /// Derive an `AeadKey` and an `AeadNonce` from the `WelcomeSecret`,
    /// consuming it in the process.
    pub(crate) fn derive_welcome_key_nonce(
        self,
        ciphersuite: &Ciphersuite,
    ) -> (AeadKey, AeadNonce) {
        let welcome_nonce = AeadNonce::from_welcome_secret(ciphersuite, &self);
        let welcome_key = AeadKey::from_welcome_secret(ciphersuite, &self);
        (welcome_key, welcome_nonce)
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
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
        EpochSecret {
            secret: intermediate_secret.secret.kdf_expand_label(
                ciphersuite,
                "epoch",
                &group_context.serialized(),
                ciphersuite.hash_length(),
            ),
        }
    }
}

/// The `EncryptionSecret` is used to create a `SecretTree`.
#[derive(Serialize, Deserialize, Default)] // FIXME: what do we want serialization do here?
pub(crate) struct EncryptionSecret {
    secret: Secret,
}

impl EncryptionSecret {
    /// Derive an encryption secret from a reference to an `EpochSecret`.
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        EncryptionSecret {
            secret: epoch_secret.secret.derive_secret(ciphersuite, "encryption"),
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
    pub(crate) fn from_random(length: usize) -> Self {
        EncryptionSecret {
            secret: Secret::random(length),
        }
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
    }
}

#[cfg(test)]
#[doc(hidden)]
impl From<&[u8]> for EncryptionSecret {
    fn from(bytes: &[u8]) -> Self {
        Self {
            secret: Secret::from(bytes),
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
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret.secret.derive_secret(ciphersuite, "exporter");
        ExporterSecret { secret }
    }

    /// Get the `Secret` of the `ExporterSecret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
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
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret
            .secret
            .derive_secret(ciphersuite, "authentication");
        Self { secret }
    }

    /// Get the internal `Secret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
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
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret.secret.derive_secret(ciphersuite, "external");
        Self { secret }
    }

    /// Derive the external keypair for External Commits
    pub(crate) fn derive_external_keypair(&self, ciphersuite: &Ciphersuite) -> HPKEKeyPair {
        ciphersuite.derive_hpke_keypair(&self.secret)
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
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
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret
            .secret
            .derive_secret(ciphersuite, "confirmation");
        Self { secret }
    }

    /// Get the internal `Secret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
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
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret.secret.derive_secret(ciphersuite, "membership");
        Self { secret }
    }

    /// Get the internal `Secret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    pub(crate) fn from_secret(secret: Secret) -> Self {
        Self { secret }
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
    }
}

/// A secret used in cross-group operations.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ResumptionSecret {
    secret: Secret,
}

impl ResumptionSecret {
    /// Derive an `ResumptionSecret` from an `EpochSecret`.
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret.secret.derive_secret(ciphersuite, "resumption");
        Self { secret }
    }

    /// Get the internal `Secret`.
    // Will be used in #141
    pub(crate) fn _secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
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
    fn new(ciphersuite: &Ciphersuite, epoch_secret: &EpochSecret) -> Self {
        let secret = epoch_secret
            .secret
            .derive_secret(ciphersuite, "sender data");
        SenderDataSecret { secret }
    }

    /// Get the `Secret` of the `ExporterSecret`.
    pub(crate) fn secret(&self) -> &Secret {
        &self.secret
    }

    #[cfg(test)]
    #[doc(hidden)]
    pub fn from_random(length: usize) -> Self {
        Self {
            secret: Secret::random(length),
        }
    }

    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.secret.to_bytes()
    }
}

#[cfg(test)]
#[doc(hidden)]
impl From<&[u8]> for SenderDataSecret {
    fn from(bytes: &[u8]) -> Self {
        Self {
            secret: Secret::from(bytes),
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

    // XXX: This is currently only used in tests but will be used in future.
    #[cfg(test)]
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
        // XXX: `take` will be stabilized in 1.50 (release date 11.2.2021)
        // We need to do this until then.
        // https://github.com/rust-lang/rust/issues/71395
        // Note that we need to use a `RefCell` and not a `Cell` here because
        // we don't want to implement `Copy` for secrets.
        self.encryption_secret.replace(EncryptionSecret::default())
    }

    /// Derive `EpochSecrets` from an `EpochSecret`.
    /// If the `init_secret` argument is `true`, the init secret is derived and
    /// part of the `EpochSecrets`. Otherwise not.
    fn new(ciphersuite: &Ciphersuite, epoch_secret: EpochSecret, init_secret: bool) -> Self {
        let sender_data_secret = SenderDataSecret::new(ciphersuite, &epoch_secret);
        let encryption_secret = EncryptionSecret::new(ciphersuite, &epoch_secret);
        let exporter_secret = ExporterSecret::new(ciphersuite, &epoch_secret);
        let authentication_secret = AuthenticationSecret::new(ciphersuite, &epoch_secret);
        let external_secret = ExternalSecret::new(ciphersuite, &epoch_secret);
        let confirmation_key = ConfirmationKey::new(ciphersuite, &epoch_secret);
        let membership_key = MembershipKey::new(ciphersuite, &epoch_secret);
        let resumption_secret = ResumptionSecret::new(ciphersuite, &epoch_secret);

        let init_secret = if init_secret {
            Some(InitSecret::new(ciphersuite, epoch_secret))
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

    #[cfg(test)]
    #[doc(hidden)]
    pub(crate) fn sender_data_secret_mut(&mut self) -> &mut SenderDataSecret {
        &mut self.sender_data_secret
    }
}
