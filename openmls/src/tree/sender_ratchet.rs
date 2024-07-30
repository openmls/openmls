//! ### Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable `LibraryError`.
//! This means that some functions that are not expected to fail and throw an
//! error, will still return a `Result` since they may throw a `LibraryError`.

use openmls_traits::crypto::OpenMlsCrypto;
use std::collections::VecDeque;

use openmls_traits::types::Ciphersuite;

use crate::ciphersuite::{AeadNonce, *};
use crate::tree::secret_tree::*;

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
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
/// secrets around.
#[derive(Serialize, Deserialize)]
#[cfg_attr(any(feature = "test-utils", test), derive(PartialEq, Clone))]
#[cfg_attr(any(feature = "crypto-debug", test), derive(Debug))]
pub(crate) enum SenderRatchet {
    EncryptionRatchet(RatchetSecret),
    DecryptionRatchet(DecryptionRatchet),
}

impl SenderRatchet {
    #[cfg(test)]
    pub(crate) fn generation(&self) -> Generation {
        match self {
            SenderRatchet::EncryptionRatchet(enc_ratchet) => enc_ratchet.generation(),
            SenderRatchet::DecryptionRatchet(dec_ratchet) => dec_ratchet.generation(),
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

    /// Remove elements from the `past_secrets` queue until it is within the
    /// bounds determined by the [`SenderRatchetConfiguration`].
    fn prune_past_secrets(&mut self, configuration: &SenderRatchetConfiguration) {
        self.past_secrets
            .truncate(configuration.out_of_order_tolerance() as usize)
    }

    /// Get the generation of the ratchet head.
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
        // If generation is too distant in the future
        if self.generation() < u32::MAX - configuration.maximum_forward_distance()
            && generation > self.generation() + configuration.maximum_forward_distance()
        {
            return Err(SecretTreeError::TooDistantInTheFuture);
        }
        // If generation id too distant in the past
        if generation < self.generation()
            && (self.generation() - generation) > configuration.out_of_order_tolerance()
        {
            log::error!("  Generation is too far in the past (broke out of order tolerance ({}) {generation} < {}).", configuration.out_of_order_tolerance(), self.generation());
            return Err(SecretTreeError::TooDistantInThePast);
        }
        // If generation is the one the ratchet is currently at or in the future
        if generation >= self.generation() {
            // Ratchet the chain forward as far as necessary
            for _ in 0..(generation - self.generation()) {
                // Derive the key material
                let ratchet_secrets = {
                    self.ratchet_head
                        .ratchet_forward(crypto, ciphersuite)
                        .map(|(_, key_material)| key_material)
                }?;
                // Add it to the front of the queue
                self.past_secrets.push_front(Some(ratchet_secrets));
            }
            let ratchet_secrets = {
                self.ratchet_head
                    .ratchet_forward(crypto, ciphersuite)
                    .map(|(_, key_material)| key_material)
            }?;
            // Add an entry to the past secrets queue to keep indexing consistent.
            self.past_secrets.push_front(None);
            self.prune_past_secrets(configuration);
            Ok(ratchet_secrets)
        } else {
            // If the requested generation is within the window of past secrets,
            // we should get a positive index.
            let window_index = ((self.generation() - generation) as i32) - 1;
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
