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
    aead::Mode as HpkeAeadMode, kdf::Mode as HpkeKdfMode, kem::Mode as KemMode,
    HPKEKeyPair as RealHPKEKeyPair, HPKEPrivateKey as RealHPKEPrivateKey,
    HPKEPublicKey as RealHPKEPublicKey, Hpke, Mode,
};

// TODO: re-export for other parts of the library when we can use it
// pub(crate) use hpke::{HPKEKeyPair, HPKEPrivateKey, HPKEPublicKey};

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

// TODO: remove these and use the proper types from HPKE.

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEPublicKey {
    value: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEPrivateKey {
    value: Vec<u8>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEKeyPair {
    private_key: HPKEPrivateKey,
    public_key: HPKEPublicKey,
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

#[derive(PartialEq, Copy, Clone, Debug)]
pub struct Ciphersuite {
    name: CiphersuiteName,
    signature: SignatureMode,
    hpke_kem: KemMode,
    hpke_kdf: HpkeKdfMode,
    hpke_aead: HpkeAeadMode,
    aead: AeadMode,
    hash: DigestMode,
    hmac: HmacMode,
}

impl Ciphersuite {
    /// Create a new ciphersuite from the given `name`.
    pub fn new(name: CiphersuiteName) -> Self {
        Ciphersuite {
            name,
            signature: get_signature_from_suite(&name),
            hpke_kem: get_kem_from_suite(&name),
            hpke_kdf: get_hpke_kdf_from_suite(&name),
            hpke_aead: get_hpke_aead_from_suite(&name),
            aead: get_aead_from_suite(&name),
            hash: get_hash_from_suite(&name),
            hmac: get_kdf_from_suite(&name),
        }
    }

    /// Sign a `msg` with the given `sk`.
    pub(crate) fn sign(
        &self,
        sk: &SignaturePrivateKey,
        msg: &[u8],
    ) -> Result<Signature, SignatureError> {
        let (hash, nonce) = match self.signature {
            SignatureMode::Ed25519 => (None, None),
            SignatureMode::P256 => (Some(self.hash), Some(p256_ecdsa_random_nonce())),
        };
        match sign(self.signature, hash, &sk.value, msg, nonce.as_ref()) {
            Ok(s) => Ok(Signature { value: s }),
            Err(e) => Err(e),
        }
    }

    /// Verify a `msg` against `sig` and `pk`.
    pub(crate) fn verify(&self, sig: &Signature, pk: &SignaturePublicKey, msg: &[u8]) -> bool {
        verify(self.signature, Some(self.hash), &pk.value, &sig.value, msg).unwrap()
    }

    /// Create a new signature key pair and return it.
    pub fn new_signature_keypair(&self) -> SignatureKeypair {
        let (sk, pk) = match signature_key_gen(self.signature) {
            Ok((sk, pk)) => (sk, pk),
            Err(e) => panic!("Key generation really shouldn't fail. {:?}", e),
        };
        SignatureKeypair {
            ciphersuite: *self,
            private_key: SignaturePrivateKey { value: sk.to_vec() },
            public_key: SignaturePublicKey { value: pk.to_vec() },
        }
    }

    /// Hash `payload` and return the digest.
    pub(crate) fn hash(&self, payload: &[u8]) -> Vec<u8> {
        hash(self.hash, payload)
    }

    /// Get the output length of the kdf.
    pub(crate) fn hkdf_length(&self) -> usize {
        get_tag_size(self.hmac)
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
        // TODO: put hpke in the ciphersuite.
        let hpke = Hpke::new(Mode::Base, self.hpke_kem, self.hpke_kdf, self.hpke_aead);
        let (kem_output, ciphertext) = hpke
            .seal(&pk_r.into(), info, aad, ptxt, None, None, None)
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
        // TODO: put hpke in the ciphersuite.
        let hpke = Hpke::new(Mode::Base, self.hpke_kem, self.hpke_kdf, self.hpke_aead);
        hpke.open(
            &input.kem_output,
            &sk_r.into(),
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
        // TODO: put hpke in the ciphersuite.
        let hpke = Hpke::new(Mode::Base, self.hpke_kem, self.hpke_kdf, self.hpke_aead);
        HPKEKeyPair::from(hpke.generate_key_pair())
    }
}

// Some internals.

impl HPKEPublicKey {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self {
            value: bytes.to_vec(),
        }
    }

    fn into(&self) -> RealHPKEPublicKey {
        RealHPKEPublicKey::new(self.value.clone())
    }
    fn from(k: RealHPKEPublicKey) -> Self {
        Self {
            value: k.as_slice().to_vec(),
        }
    }
}

impl HPKEPrivateKey {
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
    pub(crate) fn from_slice(bytes: &[u8]) -> Self {
        Self {
            value: bytes.to_vec(),
        }
    }
    pub(crate) fn public_key(&self, hpke_kem: KemMode) -> HPKEPublicKey {
        let pk = match hpke_kem {
            KemMode::DhKemP256 => p256_base(&self.value).unwrap().to_vec(),
            KemMode::DhKemP384 => unimplemented!(),
            KemMode::DhKemP521 => unimplemented!(),
            KemMode::DhKem25519 => {
                let mut sk = [0u8; 32];
                sk.copy_from_slice(&self.value);
                x25519_base(&sk).to_vec()
            }
            KemMode::DhKem448 => unimplemented!(),
        };
        HPKEPublicKey::from_slice(&pk)
    }

    fn into(&self) -> RealHPKEPrivateKey {
        RealHPKEPrivateKey::new(self.value.clone())
    }
    fn from(k: RealHPKEPrivateKey) -> Self {
        Self {
            value: k.as_slice().to_vec(),
        }
    }
}

impl HPKEKeyPair {
    /// Derive a new key pair for the HPKE KEM with the given input key material.
    pub(crate) fn derive(ikm: &[u8], ciphersuite: &Ciphersuite) -> Self {
        let key_pair = Hpke::new(
            Mode::Base,
            ciphersuite.hpke_kem,
            ciphersuite.hpke_kdf,
            ciphersuite.hpke_aead,
        )
        .derive_key_pair(ikm);
        Self {
            private_key: HPKEPrivateKey {
                value: key_pair.get_private_key_ref().as_slice().to_vec(),
            },
            public_key: HPKEPublicKey {
                value: key_pair.get_public_key_ref().as_slice().to_vec(),
            },
        }
    }

    // FIXME: remove
    /// Build a new HPKE key pair from the given `bytes`.
    pub(crate) fn from_slice(bytes: &[u8], ciphersuite: &Ciphersuite) -> Self {
        let private_key = HPKEPrivateKey::from_slice(bytes);
        let public_key = private_key.public_key(ciphersuite.hpke_kem);
        Self {
            private_key,
            public_key,
        }
    }

    /// Get the private key.
    pub(crate) fn get_private_key(&self) -> HPKEPrivateKey {
        self.private_key.clone()
    }

    /// Get the public key.
    pub(crate) fn get_public_key(&self) -> HPKEPublicKey {
        self.public_key.clone()
    }

    fn into(&self) -> RealHPKEKeyPair {
        RealHPKEKeyPair::new(
            self.private_key.value.clone(),
            self.public_key.value.clone(),
        )
    }
    fn from(k: RealHPKEKeyPair) -> Self {
        Self {
            private_key: HPKEPrivateKey::from_slice(k.get_private_key_ref().as_slice()),
            public_key: HPKEPublicKey::from_slice(k.get_public_key_ref().as_slice()),
        }
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
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

impl SignatureKeypair {
    pub fn sign(&self, payload: &[u8]) -> Result<Signature, SignatureError> {
        self.ciphersuite.sign(&self.private_key, payload)
    }

    /// Get a reference to the private key.
    pub fn get_private_key(&self) -> &SignaturePrivateKey {
        &self.private_key
    }

    /// Get a reference to the public key.
    pub fn get_public_key(&self) -> &SignaturePublicKey {
        &self.public_key
    }
}

#[test]
fn test_sign_verify() {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let keypair = ciphersuite.new_signature_keypair();
    let payload = &[1, 2, 3];
    let signature = ciphersuite
        .sign(keypair.get_private_key(), payload)
        .unwrap();
    assert!(ciphersuite.verify(&signature, keypair.get_public_key(), payload));
}
