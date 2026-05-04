//! ### Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable `LibraryError`.
//! This means that some functions that are not expected to fail and throw an
//! error, will still return a `Result` since they may throw a `LibraryError`.

#[cfg(feature = "virtual-clients-draft")]
use std::collections::BTreeMap;
use std::collections::VecDeque;
#[cfg(feature = "virtual-clients-draft")]
use std::mem;

use openmls_traits::crypto::OpenMlsCrypto;

use openmls_traits::types::Ciphersuite;

use crate::ciphersuite::{AeadNonce, *};
use crate::tree::secret_tree::*;
#[cfg(feature = "virtual-clients-draft")]
use crate::utils::vector_converter;

use super::*;

/// The generation of a given [`SenderRatchet`].
pub(crate) type Generation = u32;
/// Stores the configuration parameters for `DecryptionRatchet`s.
///
/// **Parameters**
///
/// - out_of_order_tolerance:
///   This parameter defines a window for which decryption secrets are kept.
///   This is useful in case the DS cannot guarantee that all application messages have total order within an epoch.
///   Use this carefully, since keeping decryption secrets affects forward secrecy within an epoch.
///   The default value is 5.
/// - maximum_forward_distance:
///   This parameter defines how many incoming messages can be skipped. This is useful if the DS
///   drops application messages. The default value is 1000.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderRatchetConfiguration {
    out_of_order_tolerance: Generation,
    maximum_forward_distance: Generation,
}

impl SenderRatchetConfiguration {
    /// Create a new configuration
    pub fn new(out_of_order_tolerance: Generation, maximum_forward_distance: Generation) -> Self {
        Self {
            out_of_order_tolerance,
            maximum_forward_distance,
        }
    }
    /// Get a reference to the sender ratchet configuration's out of order tolerance.
    pub fn out_of_order_tolerance(&self) -> Generation {
        self.out_of_order_tolerance
    }

    /// Get a reference to the sender ratchet configuration's maximum forward distance.
    pub fn maximum_forward_distance(&self) -> Generation {
        self.maximum_forward_distance
    }
}

impl Default for SenderRatchetConfiguration {
    fn default() -> Self {
        Self::new(5, 1000)
    }
}

/// The key material derived from a [`RatchetSecret`] meant for use with a
/// nonce-based symmetric encryption scheme.
pub(crate) type RatchetKeyMaterial = (AeadKey, AeadNonce);

/// A ratchet that can output key material either for encryption
/// ([`EncryptionRatchet`](SenderRatchet)) or decryption
/// ([`DecryptionRatchet`]). A [`DecryptionRatchet`] can be configured with an
/// `out_of_order_tolerance` and a `maximum_forward_distance` (see
/// [`SenderRatchetConfiguration`]) while an Encryption Ratchet never keeps past
/// secrets around. With the `virtual-clients-draft` feature, own sender
/// ratchets are [`DualUseRatchet`]s, which can output key material for both
/// encryption and decryption.
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
pub(crate) enum SenderRatchet {
    EncryptionRatchet(RatchetSecret),
    DecryptionRatchet(DecryptionRatchet),
    #[cfg(feature = "virtual-clients-draft")]
    DualUseRatchet(DualUseRatchet),
}

impl SenderRatchet {
    #[cfg(test)]
    pub(crate) fn generation(&self) -> Generation {
        match self {
            SenderRatchet::EncryptionRatchet(enc_ratchet) => enc_ratchet.generation(),
            SenderRatchet::DecryptionRatchet(dec_ratchet) => dec_ratchet.generation(),
            #[cfg(feature = "virtual-clients-draft")]
            SenderRatchet::DualUseRatchet(dual_ratchet) => dual_ratchet.generation(),
        }
    }
}

/// The core of both types of [`SenderRatchet`]. It contains the current head of
/// the ratchet chain, as well as its current [`Generation`]. It can be
/// initialized with a given secret and then ratcheted forward, outputting
/// [`RatchetKeyMaterial`] and increasing its [`Generation`] each time.
#[derive(Debug, Serialize, Deserialize, Default)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
pub(crate) struct RatchetSecret {
    secret: Secret,
    generation: Generation,
}

impl RatchetSecret {
    /// Create an initial [`RatchetSecret`] with `generation = 0` from the given
    /// [`Secret`].
    pub(crate) fn initial_ratchet_secret(secret: Secret) -> Self {
        Self {
            secret,
            generation: 0,
        }
    }

    /// Return the generation of this [`RatchetSecret`].
    pub(crate) fn generation(&self) -> Generation {
        self.generation
    }

    /// Consume this [`RatchetSecret`] to derive a pair of [`RatchetSecrets`],
    /// as well as the [`RatchetSecret`] of the next generation and return both.
    pub(crate) fn ratchet_forward(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        ciphersuite: Ciphersuite,
    ) -> Result<(Generation, RatchetKeyMaterial), SecretTreeError> {
        log::trace!("Ratcheting forward in generation {}.", self.generation);
        log_crypto!(trace, "    with secret {:x?}", self.secret);

        // Check if the generation is getting too large.
        if self.generation == u32::MAX {
            return Err(SecretTreeError::RatchetTooLong);
        }
        let nonce = derive_tree_secret(
            ciphersuite,
            &self.secret,
            "nonce",
            self.generation,
            ciphersuite.aead_nonce_length(),
            crypto,
        )?;
        let key = derive_tree_secret(
            ciphersuite,
            &self.secret,
            "key",
            self.generation,
            ciphersuite.aead_key_length(),
            crypto,
        )?;
        self.secret = derive_tree_secret(
            ciphersuite,
            &self.secret,
            "secret",
            self.generation,
            ciphersuite.hash_length(),
            crypto,
        )?;
        let generation = self.generation;
        self.generation += 1;
        Ok((
            generation,
            (
                AeadKey::from_secret(key, ciphersuite),
                AeadNonce::from_secret(nonce),
            ),
        ))
    }

    #[cfg(test)]
    pub(crate) fn set_generation(&mut self, generation: Generation) {
        self.generation = generation
    }
}

/// [`SenderRatchet`] used to derive key material for decryption. It keeps the
/// [`RatchetKeyMaterial`] of epochs around until they are retrieved. This
/// behaviour can be configured via the `out_of_order_tolerance` and
/// `maximum_forward_distance` of the given [`SenderRatchetConfiguration`].
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
pub struct DecryptionRatchet {
    past_secrets: VecDeque<Option<RatchetKeyMaterial>>,
    ratchet_head: RatchetSecret,
}

impl DecryptionRatchet {
    /// Creates e new SenderRatchet
    pub(crate) fn new(secret: Secret) -> Self {
        Self {
            past_secrets: VecDeque::new(),
            ratchet_head: RatchetSecret::initial_ratchet_secret(secret),
        }
    }

    /// Get the generation of the ratchet head.
    #[cfg(test)]
    pub(crate) fn generation(&self) -> Generation {
        self.ratchet_head.generation()
    }

    #[cfg(test)]
    pub(crate) fn ratchet_secret_mut(&mut self) -> &mut RatchetSecret {
        &mut self.ratchet_head
    }

    /// Gets a secret from the SenderRatchet. Returns an error if the generation
    /// is out of bound.
    pub(crate) fn secret_for_decryption(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        generation: Generation,
        configuration: &SenderRatchetConfiguration,
    ) -> Result<RatchetKeyMaterial, SecretTreeError> {
        log::debug!("secret_for_decryption");
        let head_generation = self.ratchet_head.generation();
        // If generation is too distant in the future
        if head_generation < u32::MAX - configuration.maximum_forward_distance()
            && generation > head_generation + configuration.maximum_forward_distance()
        {
            return Err(SecretTreeError::TooDistantInTheFuture);
        }
        // If generation is too distant in the past
        if generation < head_generation
            && (head_generation - generation) > configuration.out_of_order_tolerance()
        {
            log::error!("  Generation is too far in the past (broke out of order tolerance ({}) {generation} < {head_generation}).", configuration.out_of_order_tolerance());
            return Err(SecretTreeError::TooDistantInThePast);
        }
        // If generation is the one the ratchet is currently at or in the future
        if generation >= head_generation {
            // Ratchet the chain forward as far as necessary
            for _ in 0..(generation - head_generation) {
                // Derive the key material
                let ratchet_secrets = self
                    .ratchet_head
                    .ratchet_forward(crypto, ciphersuite)
                    .map(|(_, key_material)| key_material)?;
                // Add it to the front of the queue
                self.past_secrets.push_front(Some(ratchet_secrets));
            }
            let ratchet_secrets = self
                .ratchet_head
                .ratchet_forward(crypto, ciphersuite)
                .map(|(_, key_material)| key_material)?;
            // Add an entry to the past secrets queue to keep indexing consistent.
            self.past_secrets.push_front(None);
            self.past_secrets
                .truncate(configuration.out_of_order_tolerance() as usize);
            Ok(ratchet_secrets)
        } else {
            // If the requested generation is within the window of past secrets,
            // we should get a positive index.
            let window_index = ((head_generation - generation) as i32) - 1;
            // We might not have the key material (e.g. we might have discarded
            // it when generating an encryption secret).
            let index = if window_index >= 0 {
                window_index as usize
            } else {
                log::error!("  Generation is too far in the past (not in the window).");
                return Err(SecretTreeError::TooDistantInThePast);
            };
            // Get the relevant secrets from the past secrets queue.
            self.past_secrets
                .get_mut(index)
                .ok_or(SecretTreeError::IndexOutOfBounds)?
                // We use take here to replace the entry in the `past_secrets`
                // with `None`, thus achieving FS for that secret as soon as the
                // caller of this function drops it.
                .take()
                // If the requested generation was used to decrypt a message
                // earlier, throw an error.
                .ok_or(SecretTreeError::SecretReuseError)
        }
    }
}

/// [`SenderRatchet`] used for own ratchets when the `virtual-clients-draft`
/// feature is enabled. It supports both encryption and decryption: encryption
/// is needed to send messages, while decryption lets the local member also
/// decrypt their own ciphertexts (e.g. when receiving a message encrypted by
/// another emulating client). Encryption secrets are kept in a past-secrets
/// window like a [`DecryptionRatchet`] until they are explicitly dropped by
/// confirming the corresponding generation via
/// [`Self::delete_secret_for_generation`].
#[cfg(feature = "virtual-clients-draft")]
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
pub struct DualUseRatchet {
    #[serde(with = "vector_converter")]
    past_secrets: BTreeMap<Generation, DualUsePastSecret>,
    ratchet_head: RatchetSecret,
}

#[cfg(feature = "virtual-clients-draft")]
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
enum DualUsePastSecret {
    AwaitingConfirmation(RatchetKeyMaterial),
    RetainedForDecryption(RetainedDecryptionSecret),
}

#[cfg(feature = "virtual-clients-draft")]
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
enum RetainedDecryptionSecret {
    Available(RatchetKeyMaterial),
    Consumed,
}

#[cfg(feature = "virtual-clients-draft")]
impl DualUsePastSecret {
    fn take_for_decryption(&mut self) -> Result<RatchetKeyMaterial, SecretTreeError> {
        match mem::replace(
            self,
            Self::RetainedForDecryption(RetainedDecryptionSecret::Consumed),
        ) {
            Self::AwaitingConfirmation(ratchet_secret)
            | Self::RetainedForDecryption(RetainedDecryptionSecret::Available(ratchet_secret)) => {
                *self = Self::RetainedForDecryption(RetainedDecryptionSecret::Consumed);
                Ok(ratchet_secret)
            }
            Self::RetainedForDecryption(RetainedDecryptionSecret::Consumed) => {
                *self = Self::RetainedForDecryption(RetainedDecryptionSecret::Consumed);
                Err(SecretTreeError::SecretReuseError)
            }
        }
    }

    fn is_retained_for_decryption(&self) -> bool {
        matches!(self, Self::RetainedForDecryption(_))
    }
}

#[cfg(feature = "virtual-clients-draft")]
impl DualUseRatchet {
    pub(crate) fn new(secret: Secret) -> Self {
        Self {
            past_secrets: BTreeMap::new(),
            ratchet_head: RatchetSecret::initial_ratchet_secret(secret),
        }
    }

    pub(crate) fn generation(&self) -> Generation {
        self.ratchet_head.generation()
    }

    /// Discard the cached encryption secret for a previously emitted
    /// generation. Call this to confirm a sent message and drop the
    /// corresponding key material for forward secrecy.
    ///
    /// No-op if the requested generation is at or beyond the ratchet head
    /// (i.e. nothing has been emitted yet for that generation).
    pub(crate) fn delete_secret_for_generation(&mut self, generation: Generation) {
        let head = self.generation();
        if generation >= head {
            return;
        }
        if matches!(
            self.past_secrets.get(&generation),
            Some(DualUsePastSecret::AwaitingConfirmation(_))
        ) {
            self.past_secrets.remove(&generation);
        }
    }

    /// Gets a secret for encryption. The secret is also recorded in the
    /// past-secrets window so the caller can later confirm and drop it.
    ///
    /// The cache is not pruned here: emitted encryption secrets are only
    /// cleared by an explicit call to [`Self::delete_secret_for_generation`]
    /// (i.e. confirming the message). Auto-pruning at this point could drop
    /// unconfirmed secrets the caller still intends to confirm.
    pub(crate) fn secret_for_encryption(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<(u32, RatchetKeyMaterial), SecretTreeError> {
        let generation = self.ratchet_head.generation();
        let ratchet_secrets = self
            .ratchet_head
            .ratchet_forward(crypto, ciphersuite)
            .map(|(_, key_material)| key_material)?;
        self.past_secrets.insert(
            generation,
            DualUsePastSecret::AwaitingConfirmation(ratchet_secrets.clone()),
        );
        Ok((generation, ratchet_secrets))
    }

    /// Gets a secret for decryption.
    ///
    /// The receive-side retention window is computed only from generations
    /// retained for decryption because encryption also advances the derivation
    /// head. Local sends don't enter this window. Unconfirmed encryption secrets
    /// are retained even if they fall outside the receive window.
    pub(crate) fn secret_for_decryption(
        &mut self,
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        generation: Generation,
        configuration: &SenderRatchetConfiguration,
    ) -> Result<RatchetKeyMaterial, SecretTreeError> {
        log::debug!("secret_for_decryption");
        let head_generation = self.ratchet_head.generation();
        if head_generation < u32::MAX - configuration.maximum_forward_distance()
            && generation > head_generation + configuration.maximum_forward_distance()
        {
            return Err(SecretTreeError::TooDistantInTheFuture);
        }

        let ratchet_secrets = if generation >= head_generation {
            for skipped_generation in head_generation..generation {
                let ratchet_secrets = self
                    .ratchet_head
                    .ratchet_forward(crypto, ciphersuite)
                    .map(|(_, key_material)| key_material)?;
                self.past_secrets.insert(
                    skipped_generation,
                    DualUsePastSecret::RetainedForDecryption(RetainedDecryptionSecret::Available(
                        ratchet_secrets,
                    )),
                );
            }
            let ratchet_secrets = self
                .ratchet_head
                .ratchet_forward(crypto, ciphersuite)
                .map(|(_, key_material)| key_material)?;
            self.past_secrets.insert(
                generation,
                DualUsePastSecret::RetainedForDecryption(RetainedDecryptionSecret::Consumed),
            );
            ratchet_secrets
        } else {
            let Some(entry) = self.past_secrets.get_mut(&generation) else {
                return Err(self.error_for_missing_past_secret(generation));
            };
            entry.take_for_decryption()?
        };

        self.prune_past_secrets(configuration);
        Ok(ratchet_secrets)
    }

    fn error_for_missing_past_secret(&self, generation: Generation) -> SecretTreeError {
        if self
            .past_secrets
            .iter()
            .find_map(|(retained_generation, entry)| {
                entry
                    .is_retained_for_decryption()
                    .then_some(*retained_generation)
            })
            .is_some_and(|oldest_generation| generation < oldest_generation)
        {
            log::error!("  Generation is too far in the past (not in the window).");
            SecretTreeError::TooDistantInThePast
        } else {
            SecretTreeError::SecretReuseError
        }
    }

    fn prune_past_secrets(&mut self, configuration: &SenderRatchetConfiguration) {
        let excess_retained_decryption_secrets = self
            .past_secrets
            .values()
            .filter(|entry| entry.is_retained_for_decryption())
            .count()
            .saturating_sub(configuration.out_of_order_tolerance() as usize);

        let generations_to_prune = self
            .past_secrets
            .iter()
            .filter_map(|(generation, entry)| {
                entry.is_retained_for_decryption().then_some(*generation)
            })
            .take(excess_retained_decryption_secrets)
            .collect::<Vec<_>>();

        for generation in generations_to_prune {
            self.past_secrets.remove(&generation);
        }
    }
}
