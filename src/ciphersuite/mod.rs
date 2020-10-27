// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

//! Ciphersuites for MLS
//!
//! This file contains the API to interact with ciphersuites.
//! See `codec.rs` and `ciphersuites.rs` for internals.

use evercrypt::prelude::*;
use hpke::{
    aead::Mode as HpkeAeadMode, kdf::Mode as HpkeKdfMode, kem::Mode as KemMode, Hpke, Mode,
};
use serde::{Deserialize, Serialize};

// re-export for other parts of the library when we can use it
pub(crate) use hpke::{HPKEKeyPair, HPKEPrivateKey, HPKEPublicKey};

mod ciphersuites;
mod codec;
pub(crate) mod signable;
use ciphersuites::*;

#[cfg(test)]
mod test_ciphersuite;

pub const NONCE_BYTES: usize = 12;
pub const CHACHA_KEY_BYTES: usize = 32;
pub const AES_128_KEY_BYTES: usize = 16;
pub const AES_256_KEY_BYTES: usize = 32;
pub const TAG_BYTES: usize = 16;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CiphersuiteName {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
}

#[derive(Debug)]
pub enum HKDFError {
    InvalidLength,
}

/// 7.7. Update Paths
///
/// ```text
/// struct {
///     opaque kem_output<0..2^16-1>;
///     opaque ciphertext<0..2^16-1>;
/// } HPKECiphertext;
/// ```
#[derive(Debug, PartialEq, Clone)]
pub struct HpkeCiphertext {
    kem_output: Vec<u8>,
    ciphertext: Vec<u8>,
}

// ===

#[derive(Debug)]
pub enum AEADError {
    EncryptionError,
    DecryptionError,
    WrongKeyLength,
}

#[derive(Debug, PartialEq)]
pub struct AeadKey {
    value: Vec<u8>,
}

#[derive(PartialEq, Debug)]
pub struct AeadNonce {
    value: [u8; NONCE_BYTES],
}

#[derive(Debug, PartialEq, Clone)]
pub struct Signature {
    value: Vec<u8>,
}

#[derive(Clone)]
pub struct SignaturePrivateKey {
    ciphersuite: Ciphersuite,
    value: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignaturePublicKey {
    ciphersuite: Ciphersuite,
    value: Vec<u8>,
}

#[derive(Clone)]
pub struct SignatureKeypair {
    ciphersuite: Ciphersuite,
    private_key: SignaturePrivateKey,
    public_key: SignaturePublicKey,
}

#[derive(Debug)]
pub struct Ciphersuite {
    name: CiphersuiteName,
    signature: SignatureMode,
    hpke: Hpke,
    hpke_kem: KemMode,
    hpke_kdf: HpkeKdfMode,
    hpke_aead: HpkeAeadMode,
    aead: AeadMode,
    hash: DigestMode,
    hmac: HmacMode,
}

// Cloning a ciphersuite sets up a new one to make sure we don't accidentally
// carry over anything we don"t want to.
impl Clone for Ciphersuite {
    fn clone(&self) -> Self {
        Self::new(self.name)
    }
}

impl Ciphersuite {
    /// Create a new ciphersuite from the given `name`.
    pub fn new(name: CiphersuiteName) -> Self {
        let hpke_kem = get_kem_from_suite(&name).unwrap();
        let hpke_kdf = get_hpke_kdf_from_suite(&name);
        let hpke_aead = get_hpke_aead_from_suite(&name);

        Ciphersuite {
            name,
            signature: get_signature_from_suite(&name),
            hpke: Hpke::new(Mode::Base, hpke_kem, hpke_kdf, hpke_aead),
            hpke_kem,
            hpke_kdf,
            hpke_aead,
            aead: get_aead_from_suite(&name),
            hash: get_hash_from_suite(&name),
            hmac: get_kdf_from_suite(&name),
        }
    }

    /// Get the name of this ciphersuite.
    pub fn name(&self) -> CiphersuiteName {
        self.name
    }

    /// Create a new signature key pair and return it.
    pub fn new_signature_keypair(&self) -> SignatureKeypair {
        let (sk, pk) = match signature_key_gen(self.signature) {
            Ok((sk, pk)) => (sk, pk),
            Err(e) => panic!("Key generation really shouldn't fail. {:?}", e),
        };
        SignatureKeypair {
            ciphersuite: self.clone(),
            private_key: SignaturePrivateKey {
                value: sk.to_vec(),
                ciphersuite: self.clone(),
            },
            public_key: SignaturePublicKey {
                value: pk.to_vec(),
                ciphersuite: self.clone(),
            },
        }
    }

    /// Hash `payload` and return the digest.
    pub(crate) fn hash(&self, payload: &[u8]) -> Vec<u8> {
        hash(self.hash, payload)
    }

    /// Get the length of the used hash algorithm.
    pub(crate) fn hash_length(&self) -> usize {
        get_digest_size(self.hash)
    }

    /// HKDF extract.
    pub(crate) fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        hkdf_extract(self.hmac, salt, ikm)
    }

    /// HKDF expand
    pub(crate) fn hkdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, HKDFError> {
        let key = hkdf_expand(self.hmac, prk, info, okm_len);
        if key.is_empty() {
            return Err(HKDFError::InvalidLength);
        }
        Ok(key)
    }

    /// AEAD encrypt `msg` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_seal(
        &self,
        msg: &[u8],
        aad: &[u8],
        key: &AeadKey,
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AEADError> {
        let (ct, tag) = match aead_encrypt(self.aead, &key.as_slice(), msg, &nonce.value, aad) {
            Ok((ct, tag)) => (ct, tag),
            Err(_) => return Err(AEADError::EncryptionError),
        };
        let mut ciphertext = ct;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }

    /// AEAD decrypt `ciphertext` with `key`, `aad`, and `nonce`.
    pub(crate) fn aead_open(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        key: &AeadKey,
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AEADError> {
        // TODO: don't hard-code tag bytes
        if ciphertext.len() < TAG_BYTES {
            return Err(AEADError::DecryptionError);
        }
        let (ct, tag) = ciphertext.split_at(ciphertext.len() - TAG_BYTES);
        match aead_decrypt(self.aead, key.as_slice(), ct, tag, &nonce.value, aad) {
            Ok(pt) => Ok(pt),
            Err(_) => Err(AEADError::DecryptionError),
        }
    }

    /// Returns the key size of the used AEAD.
    pub(crate) fn aead_key_length(&self) -> usize {
        aead_key_size(&self.aead)
    }

    /// Returns the length of the nonce in the AEAD.
    pub(crate) fn aead_nonce_length(&self) -> usize {
        NONCE_BYTES
    }

    /// HPKE single-shot encryption of `ptxt` to `pk_r`, using `info` and `aad`.
    pub(crate) fn hpke_seal(
        &self,
        pk_r: &HPKEPublicKey,
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> HpkeCiphertext {
        let (kem_output, ciphertext) = self
            .hpke
            .seal(&pk_r, info, aad, ptxt, None, None, None)
            .unwrap();
        HpkeCiphertext {
            kem_output,
            ciphertext,
        }
    }

    /// HPKE single-shot decryption of `input` with `sk_r`, using `info` and `aad`.
    pub(crate) fn hpke_open(
        &self,
        input: &HpkeCiphertext,
        sk_r: &HPKEPrivateKey,
        info: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        self.hpke
            .open(
                &input.kem_output,
                &sk_r,
                info,
                aad,
                &input.ciphertext,
                None,
                None,
                None,
            )
            .unwrap()
    }

    /// Generate a new HPKE key pair and return it.
    pub(crate) fn new_hpke_keypair(&self) -> HPKEKeyPair {
        self.hpke.generate_key_pair()
    }

    /// Generate a new HPKE key pair and return it.
    pub(crate) fn derive_hpke_keypair(&self, ikm: &[u8]) -> HPKEKeyPair {
        self.hpke.derive_key_pair(ikm)
    }
}

impl AeadKey {
    /// Build a new key for an AEAD from `bytes`.
    pub(crate) fn from_slice(bytes: &[u8]) -> AeadKey {
        AeadKey {
            value: bytes.to_vec(),
        }
    }

    /// Get a slice to the key value.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

impl AeadNonce {
    /// Build a new nonce for an AEAD from `bytes`.
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        nonce.clone_from_slice(bytes);
        AeadNonce { value: nonce }
    }

    /// Generate a new random nonce.
    pub(crate) fn random() -> Self {
        Self {
            value: get_random_array(),
        }
    }

    /// Get a slice to the nonce value.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

impl Signature {
    pub(crate) fn new_empty() -> Signature {
        Signature { value: vec![] }
    }
}

impl SignatureKeypair {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `SignatureError`.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SignatureError> {
        self.private_key.sign(&payload)
    }

    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> bool {
        self.public_key.verify(signature, payload)
    }

    /// Get the private and public key objects
    pub fn into_tuple(self) -> (SignaturePrivateKey, SignaturePublicKey) {
        (self.private_key, self.public_key)
    }
}

impl PartialEq for SignaturePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl SignaturePublicKey {
    /// Create a new signature public key from raw key bytes.
    pub fn new(bytes: Vec<u8>, ciphersuite: Ciphersuite) -> Self {
        Self {
            value: bytes,
            ciphersuite,
        }
    }
    /// Verify a `Signature` on the `payload` byte slice with the key pair's
    /// public key.
    pub fn verify(&self, signature: &Signature, payload: &[u8]) -> bool {
        verify(
            self.ciphersuite.signature,
            Some(self.ciphersuite.hash),
            &self.value,
            &signature.value,
            payload,
        )
        .unwrap()
    }
}

impl SignaturePrivateKey {
    /// Sign the `payload` byte slice with this signature key.
    /// Returns a `Result` with a `Signature` or a `SignatureError`.
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SignatureError> {
        let (hash, nonce) = match self.ciphersuite.signature {
            SignatureMode::Ed25519 => (None, None),
            SignatureMode::P256 => (Some(self.ciphersuite.hash), Some(p256_ecdsa_random_nonce())),
        };
        match sign(
            self.ciphersuite.signature,
            hash,
            &self.value,
            payload,
            nonce.as_ref(),
        ) {
            Ok(s) => Ok(Signature { value: s }),
            Err(e) => Err(e),
        }
    }
}
