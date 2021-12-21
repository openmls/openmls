//! ### Don't Panic!
//!
//! Functions in this module should never panic. However, if there is a bug in
//! the implementation, a function will return an unrecoverable `LibraryError`.
//! This means that some functions that are not expected to fail and throw an
//! error, will still return a `Result` since they may throw a `LibraryError`.

use crate::ciphersuite::{AeadNonce, *};
use crate::tree::{index::LeafIndex, secret_tree::*};

use super::index::NodeIndex;
use super::*;

// TODO #265: This should disappear
pub(crate) const OUT_OF_ORDER_TOLERANCE: u32 = 5;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SenderRatchetConfiguration {
    out_of_order_tolerance: u32,
    maximum_forward_distance: u32,
}

impl SenderRatchetConfiguration {
    /// Create a new configuration with the following parameters:
    ///  - out_of_order_tolerance:
    /// This parameter defines a window for which decryption secrets are kept.
    /// This is useful in case the DS cannot guarantee that all application messages have total order within an epoch.
    /// Use this carefully, since keeping decryption secrets affects forward secrecy within an epoch.
    /// The dafault value is 0.
    ///  - maximum_forward_distance:
    /// This parameter defines how many incoming messages can be skipped. This is useful if the DS
    /// drops application messages. The default value is 1000.
    pub fn new(out_of_order_tolerance: u32, maximum_forward_distance: u32) -> Self {
        Self {
            out_of_order_tolerance,
            maximum_forward_distance,
        }
    }
    /// Get a reference to the sender ratchet configuration's out of order tolerance.
    pub fn out_of_order_tolerance(&self) -> u32 {
        self.out_of_order_tolerance
    }

    /// Get a reference to the sender ratchet configuration's maximum forward distance.
    pub fn maximum_forward_distance(&self) -> u32 {
        self.maximum_forward_distance
    }
}

impl Default for SenderRatchetConfiguration {
    fn default() -> Self {
        Self::new(5, 1000)
    }
}

pub type RatchetSecrets = (AeadKey, AeadNonce);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct SenderRatchet {
    index: LeafIndex,
    generation: u32,
    past_secrets: Vec<Secret>,
}

impl SenderRatchet {
    /// Creates e new SenderRatchet
    pub fn new(index: LeafIndex, secret: &Secret) -> Self {
        Self {
            index,
            generation: 0,
            past_secrets: vec![secret.clone()],
        }
    }
    /// Gets a secret from the SenderRatchet. Returns an error if the generation
    /// is out of bound.
    pub(crate) fn secret_for_decryption(
        &mut self,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        generation: u32,
        configuration: &SenderRatchetConfiguration,
    ) -> Result<RatchetSecrets, SecretTreeError> {
        // If generation is too distant in the future
        if generation > (self.generation + configuration.maximum_forward_distance()) {
            return Err(SecretTreeError::TooDistantInTheFuture);
        }
        // If generation id too distant in the past
        if generation < self.generation
            && (self.generation - generation) >= configuration.out_of_order_tolerance()
        {
            return Err(SecretTreeError::TooDistantInThePast);
        }
        // If generation is within the window
        if generation <= self.generation {
            let window_index =
                (self.past_secrets.len() as u32 - (self.generation - generation) - 1) as usize;
            // We can return a library error here, because there must be a mistake in the implementation
            let secret = self
                .past_secrets
                .get(window_index)
                .ok_or(SecretTreeError::LibraryError)?;
            let ratchet_secrets = self.derive_key_nonce(ciphersuite, backend, secret, generation);
            Ok(ratchet_secrets)
        // If generation is in the future
        } else {
            for _ in 0..(generation - self.generation) {
                if self.past_secrets.len() == configuration.out_of_order_tolerance() as usize {
                    self.past_secrets.remove(0);
                }
                // We can return a library error here, because there must be a mistake in the implementation
                let last_secret = self
                    .past_secrets
                    .last()
                    .ok_or(SecretTreeError::LibraryError)?;
                let new_secret = self.ratchet_secret(ciphersuite, backend, last_secret);
                self.past_secrets.push(new_secret);
                self.generation += 1;
            }
            let secret = match self.past_secrets.last() {
                Some(secret) => secret,
                // We return a library error because there must be a mistake in the implementation
                None => return Err(SecretTreeError::LibraryError),
            };
            let ratchet_secrets = self.derive_key_nonce(ciphersuite, backend, secret, generation);
            Ok(ratchet_secrets)
        }
    }
    /// Gets a secret from the SenderRatchet and ratchets forward
    pub fn secret_for_encryption(
        &mut self,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
    ) -> (u32, RatchetSecrets) {
        let current_path_secret = match self.past_secrets.last() {
            Some(secret) => secret.clone(),
            None => {
                panic!("Library error. PastSecrets should never be depleted in SenderRatchet.")
            }
        };
        let next_path_secret = self.ratchet_secret(ciphersuite, backend, &current_path_secret);
        let generation = self.generation;
        // Check if we have too many secrets in `past_secrets`
        if self.past_secrets.len() >= OUT_OF_ORDER_TOLERANCE as usize {
            //Drain older secrets
            let surplus = self.past_secrets.len() - OUT_OF_ORDER_TOLERANCE as usize + 1;
            self.past_secrets.drain(0..surplus);
        }
        self.past_secrets.push(next_path_secret);
        self.generation += 1;
        (
            generation,
            self.derive_key_nonce(ciphersuite, backend, &current_path_secret, generation),
        )
    }
    /// Computes the new secret
    fn ratchet_secret(
        &self,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        secret: &Secret,
    ) -> Secret {
        derive_tree_secret(
            secret,
            "secret",
            NodeIndex::from(self.index).as_u32(),
            self.generation,
            ciphersuite.hash_length(),
            backend,
        )
    }
    /// Derives a key & nonce from a secret
    fn derive_key_nonce(
        &self,
        ciphersuite: &Ciphersuite,
        backend: &impl OpenMlsCryptoProvider,
        secret: &Secret,
        generation: u32,
    ) -> RatchetSecrets {
        let tree_index = NodeIndex::from(self.index).as_u32();
        let nonce = derive_tree_secret(
            secret,
            "nonce",
            tree_index,
            generation,
            ciphersuite.aead_nonce_length(),
            backend,
        );
        let key = derive_tree_secret(
            secret,
            "key",
            tree_index,
            generation,
            ciphersuite.aead_key_length(),
            backend,
        );
        (AeadKey::from_secret(key), AeadNonce::from_secret(nonce))
    }
    /// Gets the current generation
    #[cfg(test)]
    pub(crate) fn generation(&self) -> u32 {
        self.generation
    }
}
