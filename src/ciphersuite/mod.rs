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

use crate::utils::*;
use evercrypt::prelude::*;
use hpke::*;

mod ciphersuites;
mod codec;
pub(crate) mod signable;
use ciphersuites::*;

pub const NONCE_BYTES: usize = 12;
pub const CHACHA_KEY_BYTES: usize = 32;
pub const AES_128_KEY_BYTES: usize = 16;
pub const AES_256_KEY_BYTES: usize = 32;
pub const TAG_BYTES: usize = 16;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq)]
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

#[derive(PartialEq, Copy, Clone, Debug)]
pub struct Ciphersuite {
    name: CiphersuiteName,
}

#[derive(Debug, PartialEq, Clone)]
pub struct HpkeCiphertext {
    kem_output: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEPublicKey(Vec<u8>);

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEPrivateKey(Vec<u8>);

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEKeyPair {
    private_key: HPKEPrivateKey,
    public_key: HPKEPublicKey,
}

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
    value: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SignaturePublicKey {
    value: Vec<u8>,
}

#[derive(Clone)]
pub struct SignatureKeypair {
    ciphersuite: Ciphersuite,
    private_key: SignaturePrivateKey,
    public_key: SignaturePublicKey,
}

impl Ciphersuite {
    pub fn new(name: CiphersuiteName) -> Self {
        Ciphersuite { name }
    }
    pub(crate) fn sign(&self, sk: &SignaturePrivateKey, msg: &[u8]) -> Signature {
        // TODO: add agility
        let signature_mode = get_signature_from_suite(&self.name);
        if signature_mode != SignatureMode::Ed25519 {
            panic!("Only ed25519 is currently supported");
        }
        Signature {
            value: sign(signature_mode, None, &sk.value, msg, None).unwrap(),
        }
    }
    pub(crate) fn verify(&self, sig: &Signature, pk: &SignaturePublicKey, msg: &[u8]) -> bool {
        // TODO: add agility
        let signature_mode = get_signature_from_suite(&self.name);
        if signature_mode != SignatureMode::Ed25519 {
            panic!("Only ed25519 is currently supported");
        }
        verify(signature_mode, None, &pk.value, &sig.value, msg).unwrap()
    }
    pub(crate) fn new_signature_keypair(&self) -> SignatureKeypair {
        // TODO: add agility
        let (sk, pk) = match get_signature_from_suite(&self.name) {
            SignatureMode::Ed25519 => {
                let sk = ed25519_key_gen();
                let pk = ed25519_sk2pk(&sk);
                (sk, pk)
            }
            _ => unimplemented!(),
        };
        SignatureKeypair {
            ciphersuite: *self,
            private_key: SignaturePrivateKey { value: sk.to_vec() },
            public_key: SignaturePublicKey { value: pk.to_vec() },
        }
    }
    pub(crate) fn hash(&self, payload: &[u8]) -> Vec<u8> {
        hash(get_hash_from_suite(&self.name), payload)
    }
    pub(crate) fn hash_length(&self) -> usize {
        match get_hash_from_suite(&self.name) {
            DigestMode::Sha256 => 32,
            DigestMode::Sha512 => 64,
            _ => 0,
        }
    }
    pub(crate) fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac(get_kdf_from_suite(&self.name), key, data, None)
    }
    pub(crate) fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        hkdf_extract(get_kdf_from_suite(&self.name), salt, ikm)
    }
    pub(crate) fn hkdf_expand(
        &self,
        prk: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, HKDFError> {
        // TODO: error handling
        Ok(hkdf_expand(
            get_kdf_from_suite(&self.name),
            prk,
            info,
            okm_len,
        ))
    }

    pub(crate) fn aead_seal(
        &self,
        msg: &[u8],
        aad: &[u8],
        key: &AeadKey,
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AEADError> {
        let (ct, tag) = match aead_encrypt(
            get_aead_from_suite(&self.name),
            &key.as_slice(),
            msg,
            &nonce.value,
            aad,
        ) {
            Ok((ct, tag)) => (ct, tag),
            Err(_) => return Err(AEADError::EncryptionError),
        };
        let mut ciphertext = ct;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }
    pub(crate) fn aead_open(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        key: &AeadKey,
        nonce: &AeadNonce,
    ) -> Result<Vec<u8>, AEADError> {
        if ciphertext.len() < TAG_BYTES {
            return Err(AEADError::DecryptionError);
        }
        let payload = ciphertext.to_vec();
        let (ct, tag) = payload.split_at(ciphertext.len() - TAG_BYTES);
        match aead_decrypt(
            get_aead_from_suite(&self.name),
            &key.as_slice(),
            ct,
            tag,
            &nonce.value,
            aad,
        ) {
            Ok(pt) => Ok(pt),
            Err(_) => Err(AEADError::DecryptionError),
        }
    }

    pub(crate) fn new_aead_key(&self, bytes: &[u8]) -> Result<AeadKey, AEADError> {
        if bytes.len() != self.aead_key_length() {
            Err(AEADError::WrongKeyLength)
        } else {
            Ok(AeadKey {
                value: bytes.to_vec(),
            })
        }
    }

    pub(crate) fn aead_key_length(&self) -> usize {
        match get_aead_from_suite(&self.name) {
            AeadMode::Aes128Gcm => AES_128_KEY_BYTES,
            AeadMode::Aes256Gcm => AES_256_KEY_BYTES,
            AeadMode::Chacha20Poly1305 => CHACHA_KEY_BYTES,
        }
    }

    pub(crate) fn new_aead_nonce(&self, bytes: &[u8]) -> Result<AeadNonce, AEADError> {
        if bytes.len() != NONCE_BYTES {
            return Err(AEADError::WrongKeyLength);
        }
        let mut value = [0u8; NONCE_BYTES];
        value.copy_from_slice(bytes);
        Ok(AeadNonce { value })
    }

    pub(crate) fn new_aead_nonce_random(&self) -> AeadNonce {
        self.new_aead_nonce(&randombytes(NONCE_BYTES)).unwrap()
    }

    pub(crate) fn aead_nonce_length(&self) -> usize {
        NONCE_BYTES
    }

    pub(crate) fn hpke_seal(
        &self,
        pk_r: &HPKEPublicKey,
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> HpkeCiphertext {
        let hpke = Hpke::new(
            Mode::Base,
            get_kem_from_suite(&self.name),
            get_hpke_kdf_from_suite(&self.name),
            get_hpke_aead_from_suite(&self.name),
        );
        let (kem_output, ciphertext) = hpke.seal(&pk_r.0, info, aad, ptxt, None, None, None);
        HpkeCiphertext {
            kem_output,
            ciphertext,
        }
    }
    pub(crate) fn hpke_open(
        &self,
        input: HpkeCiphertext,
        sk_r: &HPKEPrivateKey,
        info: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let hpke = Hpke::new(
            Mode::Base,
            get_kem_from_suite(&self.name),
            get_hpke_kdf_from_suite(&self.name),
            get_hpke_aead_from_suite(&self.name),
        );
        hpke.open(
            &input.kem_output,
            &sk_r.0,
            info,
            aad,
            &input.ciphertext,
            None,
            None,
            None,
        )
    }
    pub(crate) fn new_hpke_keypair(&self) -> HPKEKeyPair {
        // TODO: add agility
        match get_kem_from_suite(&self.name) {
            kem::Mode::DhKem25519 => HPKEKeyPair::from_slice(&randombytes(32)),
            _ => unimplemented!(),
        }
    }
}

// Some internals.

impl HPKEPublicKey {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl HPKEPrivateKey {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    pub(crate) fn public_key(&self) -> HPKEPublicKey {
        // TODO: add agility
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&self.0);
        let pk = x25519_base(&sk);
        HPKEPublicKey::from_slice(&pk)
    }
}

impl HPKEKeyPair {
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        let private_key = HPKEPrivateKey::from_slice(bytes);
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Get a reference to the private key.
    pub(crate) fn get_private_key(&self) -> &HPKEPrivateKey {
        &self.private_key
    }

    /// Get a reference to the public key.
    pub(crate) fn get_public_key(&self) -> &HPKEPublicKey {
        &self.public_key
    }
}

impl AeadKey {
    pub(crate) fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

impl AeadNonce {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

impl Signature {
    pub(crate) fn new_empty() -> Signature {
        Signature { value: vec![] }
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

impl SignatureKeypair {
    pub(crate) fn sign(&self, payload: &[u8]) -> Signature {
        self.ciphersuite.sign(&self.private_key, payload)
    }

    /// Get a reference to the private key.
    pub(crate) fn get_private_key(&self) -> &SignaturePrivateKey {
        &self.private_key
    }

    /// Get a reference to the public key.
    pub(crate) fn get_public_key(&self) -> &SignaturePublicKey {
        &self.public_key
    }
}
