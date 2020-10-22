use crate::ciphersuite::*;
use crate::codec::*;
use crate::tree::{index::LeafIndex, secret_tree::*};

const OUT_OF_ORDER_TOLERANCE: u32 = 5;
const MAXIMUM_FORWARD_DISTANCE: u32 = 1000;

pub type RatchetSecrets = (AeadKey, AeadNonce);

#[derive(Clone)]
pub struct SenderRatchet {
    index: LeafIndex,
    generation: u32,
    past_secrets: Vec<Vec<u8>>,
}

impl Codec for SenderRatchet {
    // fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
    //     self.ciphersuite.encode(buffer)?;
    //     self.index.encode(buffer)?;
    //     self.generation.encode(buffer)?;
    //     let len = self.past_secrets.len();
    //     (len as u32).encode(buffer)?;
    //     for i in 0..len {
    //         encode_vec(VecSize::VecU8, buffer, &self.past_secrets[i])?;
    //     }
    //     Ok(())
    // }
    // fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
    //     let ciphersuite = Ciphersuite::decode(cursor)?;
    //     let index = LeafIndex::from(u32::decode(cursor)?);
    //     let generation = u32::decode(cursor)?;
    //     let len = u32::decode(cursor)? as usize;
    //     let mut past_secrets = vec![];
    //     for _ in 0..len {
    //         let secret = decode_vec(VecSize::VecU8, cursor)?;
    //         past_secrets.push(secret);
    //     }
    //     Ok(SenderRatchet {
    //         ciphersuite,
    //         index,
    //         generation,
    //         past_secrets,
    //     })
    // }
}

impl SenderRatchet {
    /// Creates e new SenderRatchet
    pub fn new(index: LeafIndex, secret: &[u8]) -> Self {
        Self {
            index,
            generation: 0,
            past_secrets: vec![secret.to_vec()],
        }
    }
    /// Gets a secret from the SenderRatchet. Returns an error if the generation is out of bound.
    pub fn get_secret_for_decryption(
        &mut self,
        ciphersuite: &Ciphersuite,
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
            let ratchet_secrets = self.derive_key_nonce(ciphersuite, &secret, generation);
            Ok(ratchet_secrets)
        // If generation is in the future
        } else {
            for _ in 0..(generation - self.generation) {
                if self.past_secrets.len() == OUT_OF_ORDER_TOLERANCE as usize {
                    self.past_secrets.remove(0);
                }
                let new_secret =
                    self.ratchet_secret(ciphersuite, self.past_secrets.last().unwrap());
                self.past_secrets.push(new_secret);
            }
            let secret = self.past_secrets.last().unwrap();
            let ratchet_secrets = self.derive_key_nonce(ciphersuite, &secret, generation);
            self.generation = generation;
            Ok(ratchet_secrets)
        }
    }
    /// Gets a secret from the SenderRatchet and ratchets forward
    pub fn get_secret_for_encryption(
        &mut self,
        ciphersuite: &Ciphersuite,
    ) -> (u32, RatchetSecrets) {
        let current_path_secret = self.past_secrets[0].clone();
        let next_path_secret = self.ratchet_secret(ciphersuite, &current_path_secret);
        let generation = self.get_generation();
        self.past_secrets = vec![next_path_secret];
        self.generation += 1;
        (
            generation,
            self.derive_key_nonce(ciphersuite, &current_path_secret, generation),
        )
    }
    /// Computes the new secret
    fn ratchet_secret(&self, ciphersuite: &Ciphersuite, secret: &[u8]) -> Vec<u8> {
        derive_tree_secret(
            ciphersuite,
            secret,
            "secret",
            self.index.into(),
            self.generation,
            ciphersuite.hash_length(),
        )
    }
    /// Derives a key & nonce from a secret
    fn derive_key_nonce(
        &self,
        ciphersuite: &Ciphersuite,
        secret: &[u8],
        generation: u32,
    ) -> RatchetSecrets {
        let nonce = derive_tree_secret(
            &ciphersuite,
            secret,
            "nonce",
            self.index.into(),
            generation,
            ciphersuite.aead_nonce_length(),
        );
        let key = derive_tree_secret(
            &ciphersuite,
            secret,
            "key",
            self.index.into(),
            generation,
            ciphersuite.aead_key_length(),
        );
        (AeadKey::from_slice(&key), AeadNonce::from_slice(&nonce))
    }
    /// Gets the current generation
    pub(crate) fn get_generation(&self) -> u32 {
        self.generation
    }
}
