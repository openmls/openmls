use crate::ciphersuite::{AeadNonce, *};
use crate::tree::{index::LeafIndex, secret_tree::*};

use super::index::NodeIndex;
use super::*;

const OUT_OF_ORDER_TOLERANCE: u32 = 5;
const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;

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
    ) -> Result<RatchetSecrets, SecretTreeError> {
        // If generation is too distant in the future
        if generation > (self.generation + MAXIMUM_FORWARD_DISTANCE) {
            return Err(SecretTreeError::TooDistantInTheFuture);
        }
        // If generation id too distant in the past
        if generation < self.generation && (self.generation - generation) >= OUT_OF_ORDER_TOLERANCE
        {
            return Err(SecretTreeError::TooDistantInThePast);
        }
        // If generation is within the window
        if generation <= self.generation {
            let window_index =
                (self.past_secrets.len() as u32 - (self.generation - generation) - 1) as usize;
            let secret = self.past_secrets.get(window_index).unwrap().clone();
            let ratchet_secrets = self.derive_key_nonce(ciphersuite, backend, &secret, generation);
            Ok(ratchet_secrets)
        // If generation is in the future
        } else {
            for _ in 0..(generation - self.generation) {
                if self.past_secrets.len() == OUT_OF_ORDER_TOLERANCE as usize {
                    self.past_secrets.remove(0);
                }
                let new_secret =
                    self.ratchet_secret(ciphersuite, backend, self.past_secrets.last().unwrap());
                self.past_secrets.push(new_secret);
                self.generation += 1;
            }
            let secret = self.past_secrets.last().unwrap();
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
