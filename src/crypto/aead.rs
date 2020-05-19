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

use crate::kp::*;
use crate::utils::*;
use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::*;
use chacha20poly1305::ChaCha20Poly1305;
use std::*;
use zeroize::Zeroize;

#[derive(Copy, Clone)]
pub enum AEADAlgorithm {
    CHACHA20POLY1305,
    AES128GCM,
    AES256GCM,
    INVALID,
}

impl From<CipherSuite> for AEADAlgorithm {
    fn from(value: CipherSuite) -> Self {
        match value {
            CipherSuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => AEADAlgorithm::AES128GCM,
            CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => AEADAlgorithm::AES128GCM,
            CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                AEADAlgorithm::CHACHA20POLY1305
            }
            CipherSuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => AEADAlgorithm::AES256GCM,
            CipherSuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => AEADAlgorithm::AES256GCM,
            CipherSuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => {
                AEADAlgorithm::CHACHA20POLY1305
            }
            CipherSuite::Default => AEADAlgorithm::INVALID,
        }
    }
}

#[derive(Debug)]
pub enum AEADError {
    EncryptionError,
    DecryptionError,
    WrongKeyLength,
}

pub const NONCEBYTES: usize = 12;
pub const CHACHAKEYBYTES: usize = 32;
pub const AES128KEYBYTES: usize = 16;
pub const AES256KEYBYTES: usize = 32;
pub const CHACHATAGBYTES: usize = 16;

#[derive(PartialEq, Debug)]
pub struct Nonce([u8; NONCEBYTES]);

impl Nonce {
    pub fn new_random() -> Nonce {
        let random_bytes = randombytes(NONCEBYTES);
        let mut bytes: [u8; NONCEBYTES] = [0u8; NONCEBYTES];
        bytes[..NONCEBYTES].clone_from_slice(&random_bytes[..NONCEBYTES]);
        Nonce(bytes)
    }
    pub fn from_slice(slice: &[u8]) -> Result<Nonce, AEADError> {
        // TODO add ciphersuite support
        if slice.len() != NONCEBYTES {
            return Err(AEADError::WrongKeyLength);
        }
        let mut bytes = [0u8; NONCEBYTES];
        bytes.copy_from_slice(slice);
        Ok(Nonce(bytes))
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
    pub fn nonce_length(algorithm: AEADAlgorithm) -> Result<usize, AEADError> {
        match algorithm {
            AEADAlgorithm::INVALID => Err(AEADError::WrongKeyLength),
            _ => Ok(NONCEBYTES),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct AEADKey {
    value: Vec<u8>,
}

impl AEADKey {
    pub fn from_slice(algorithm: AEADAlgorithm, slice: &[u8]) -> Result<AEADKey, AEADError> {
        let key_length = AEADKey::key_length(algorithm).unwrap();
        if slice.len() != key_length {
            return Err(AEADError::WrongKeyLength);
        }
        Ok(AEADKey {
            value: slice.to_vec(),
        })
    }
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
    pub fn key_length(algorithm: AEADAlgorithm) -> Result<usize, AEADError> {
        let key_length;
        match algorithm {
            AEADAlgorithm::AES128GCM => {
                key_length = AES128KEYBYTES;
            }
            AEADAlgorithm::CHACHA20POLY1305 => {
                key_length = CHACHAKEYBYTES;
            }
            AEADAlgorithm::AES256GCM => {
                key_length = AES256KEYBYTES;
            }
            AEADAlgorithm::INVALID => return Err(AEADError::WrongKeyLength),
        };
        Ok(key_length)
    }
}

impl Drop for AEADKey {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

#[derive(PartialEq, Debug)]
pub struct ChaChaKey(pub [u8; CHACHAKEYBYTES]);

impl ChaChaKey {
    pub fn from_slice(slice: &[u8]) -> ChaChaKey {
        assert_eq!(slice.len(), CHACHAKEYBYTES);
        let mut key = [0u8; CHACHAKEYBYTES];
        key[..CHACHAKEYBYTES].clone_from_slice(&slice[..CHACHAKEYBYTES]);
        ChaChaKey(key)
    }
}

impl From<Vec<u8>> for ChaChaKey {
    fn from(v: Vec<u8>) -> ChaChaKey {
        ChaChaKey::from_slice(v.as_slice())
    }
}

impl Drop for ChaChaKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(PartialEq, Debug)]
pub struct AES128Key(pub [u8; AES128KEYBYTES]);

impl AES128Key {
    pub fn from_slice(slice: &[u8]) -> AES128Key {
        assert_eq!(slice.len(), AES128KEYBYTES);
        let mut key = [0u8; AES128KEYBYTES];
        key[..AES128KEYBYTES].clone_from_slice(&slice[..AES128KEYBYTES]);
        AES128Key(key)
    }
}

impl From<Vec<u8>> for AES128Key {
    fn from(v: Vec<u8>) -> AES128Key {
        AES128Key::from_slice(v.as_slice())
    }
}

impl Drop for AES128Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct AES256Key(pub [u8; AES256KEYBYTES]);

impl AES256Key {
    pub fn from_slice(slice: &[u8]) -> AES256Key {
        assert_eq!(slice.len(), AES256KEYBYTES);
        let mut key = [0u8; AES256KEYBYTES];
        key[..AES256KEYBYTES].clone_from_slice(&slice[..AES256KEYBYTES]);
        AES256Key(key)
    }
}

impl From<Vec<u8>> for AES256Key {
    fn from(v: Vec<u8>) -> AES256Key {
        AES256Key::from_slice(v.as_slice())
    }
}

impl Drop for AES256Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub fn aead_seal(
    algorithm: AEADAlgorithm,
    msg: &[u8],
    aad: &[u8],
    key: &AEADKey,
    nonce: &Nonce,
) -> Result<Vec<u8>, AEADError> {
    let payload = aead::Payload { msg, aad };
    let aead_nonce = GenericArray::from(nonce.0);
    match algorithm {
        AEADAlgorithm::AES128GCM => {
            let aead_key = *GenericArray::from_slice(&key.as_slice());
            let aead = Aes128Gcm::new(aead_key);
            match aead.encrypt(&aead_nonce, payload) {
                Ok(ciphertext) => Ok(ciphertext),
                Err(_) => Err(AEADError::EncryptionError),
            }
        }
        AEADAlgorithm::AES256GCM => {
            let aead_key = *GenericArray::from_slice(&key.as_slice());
            let aead = Aes256Gcm::new(aead_key);
            match aead.encrypt(&aead_nonce, payload) {
                Ok(ciphertext) => Ok(ciphertext),
                Err(_) => Err(AEADError::EncryptionError),
            }
        }
        AEADAlgorithm::CHACHA20POLY1305 => {
            let aead_key = *GenericArray::from_slice(&key.as_slice());
            let aead = ChaCha20Poly1305::new(aead_key);
            match aead.encrypt(&aead_nonce, payload) {
                Ok(ciphertext) => Ok(ciphertext),
                Err(_) => Err(AEADError::EncryptionError),
            }
        }
        _ => Err(AEADError::EncryptionError),
    }
}
pub fn aead_open(
    algorithm: AEADAlgorithm,
    ciphertext: &[u8],
    aad: &[u8],
    key: &AEADKey,
    nonce: &Nonce,
) -> Result<Vec<u8>, AEADError> {
    let payload = aead::Payload {
        msg: ciphertext,
        aad,
    };
    let aead_nonce = GenericArray::from(nonce.0);
    match algorithm {
        AEADAlgorithm::AES128GCM => {
            let aead_key = *GenericArray::from_slice(&key.as_slice());
            let aead = Aes128Gcm::new(aead_key);
            match aead.decrypt(&aead_nonce, payload) {
                Ok(plaintext) => Ok(plaintext),
                Err(_) => Err(AEADError::EncryptionError),
            }
        }
        AEADAlgorithm::AES256GCM => {
            let aead_key = *GenericArray::from_slice(&key.as_slice());
            let aead = Aes256Gcm::new(aead_key);
            match aead.decrypt(&aead_nonce, payload) {
                Ok(plaintext) => Ok(plaintext),
                Err(_) => Err(AEADError::EncryptionError),
            }
        }
        AEADAlgorithm::CHACHA20POLY1305 => {
            let aead_key = *GenericArray::from_slice(&key.as_slice());
            let aead = ChaCha20Poly1305::new(aead_key);
            match aead.decrypt(&aead_nonce, payload) {
                Ok(plaintext) => Ok(plaintext),
                Err(_) => Err(AEADError::EncryptionError),
            }
        }
        _ => Err(AEADError::DecryptionError),
    }
}
pub fn chacha_seal(
    msg: &[u8],
    aad: &[u8],
    key: &ChaChaKey,
    nonce: &Nonce,
) -> Result<Vec<u8>, AEADError> {
    let payload = aead::Payload { msg, aad };
    let aead_key = GenericArray::from(key.0);
    let aead = ChaCha20Poly1305::new(aead_key);
    let aead_nonce = GenericArray::from(nonce.0);
    match aead.encrypt(&aead_nonce, payload) {
        Ok(ciphertext) => Ok(ciphertext),
        Err(_) => Err(AEADError::EncryptionError),
    }
}

pub fn chacha_open(
    ciphertext: &[u8],
    aad: &[u8],
    key: &ChaChaKey,
    nonce: &Nonce,
) -> Result<Vec<u8>, AEADError> {
    let payload = aead::Payload {
        msg: ciphertext,
        aad,
    };
    let aead_key = GenericArray::from(key.0);
    let aead = ChaCha20Poly1305::new(aead_key);
    let aead_nonce = GenericArray::from(nonce.0);
    match aead.decrypt(&aead_nonce, payload) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(AEADError::DecryptionError),
    }
}

pub fn aes_128_seal(
    msg: &[u8],
    aad: &[u8],
    key: &AES128Key,
    nonce: &Nonce,
) -> Result<Vec<u8>, AEADError> {
    let payload = aead::Payload { msg, aad };
    let aead_key = GenericArray::from(key.0);
    let aead = Aes128Gcm::new(aead_key);
    let aead_nonce = GenericArray::from(nonce.0);
    match aead.encrypt(&aead_nonce, payload) {
        Ok(ciphertext) => Ok(ciphertext),
        Err(_) => Err(AEADError::EncryptionError),
    }
}

pub fn aes_128_open(
    ciphertext: &[u8],
    aad: &[u8],
    key: &AES128Key,
    nonce: &Nonce,
) -> Result<Vec<u8>, AEADError> {
    let payload = aead::Payload {
        msg: ciphertext,
        aad,
    };
    let aead_key = GenericArray::from(key.0);
    let aead = Aes128Gcm::new(aead_key);
    let aead_nonce = GenericArray::from(nonce.0);
    match aead.decrypt(&aead_nonce, payload) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(AEADError::DecryptionError),
    }
}

pub fn aes_256_seal(
    msg: &[u8],
    aad: &[u8],
    key: &AES256Key,
    nonce: &Nonce,
) -> Result<Vec<u8>, AEADError> {
    let payload = aead::Payload { msg, aad };
    let aead_key = GenericArray::from(key.0);
    let aead = Aes256Gcm::new(aead_key);
    let aead_nonce = GenericArray::from(nonce.0);
    match aead.encrypt(&aead_nonce, payload) {
        Ok(ciphertext) => Ok(ciphertext),
        Err(_) => Err(AEADError::EncryptionError),
    }
}

pub fn aes_256_open(
    ciphertext: &[u8],
    aad: &[u8],
    key: &AES256Key,
    nonce: &Nonce,
) -> Result<Vec<u8>, AEADError> {
    let payload = aead::Payload {
        msg: ciphertext,
        aad,
    };
    let aead_key = GenericArray::from(key.0);
    let aead = Aes256Gcm::new(aead_key);
    let aead_nonce = GenericArray::from(nonce.0);
    match aead.decrypt(&aead_nonce, payload) {
        Ok(plaintext) => Ok(plaintext),
        Err(_) => Err(AEADError::DecryptionError),
    }
}

#[test]
fn seal_open() {
    let msg = [1, 2, 3];
    let aad = [4, 5, 6];

    // ChaCha20Poly1305
    let algorithm = AEADAlgorithm::CHACHA20POLY1305;
    let key: AEADKey = AEADKey::from_slice(algorithm, &randombytes(CHACHAKEYBYTES)).unwrap();
    let nonce = Nonce::new_random();
    let encrypted = aead_seal(algorithm, &msg, &aad, &key, &nonce).unwrap();
    let decrypted = aead_open(algorithm, &encrypted, &aad, &key, &nonce).unwrap();
    assert_eq!(decrypted, msg);

    // AES128
    let algorithm = AEADAlgorithm::AES128GCM;
    let key: AEADKey = AEADKey::from_slice(algorithm, &randombytes(AES128KEYBYTES)).unwrap();
    let nonce = Nonce::new_random();
    let encrypted = aead_seal(algorithm, &msg, &aad, &key, &nonce).unwrap();
    let decrypted = aead_open(algorithm, &encrypted, &aad, &key, &nonce).unwrap();
    assert_eq!(decrypted, msg);

    // AES256
    let algorithm = AEADAlgorithm::AES256GCM;
    let key: AEADKey = AEADKey::from_slice(algorithm, &randombytes(AES256KEYBYTES)).unwrap();
    let nonce = Nonce::new_random();
    let encrypted = aead_seal(algorithm, &msg, &aad, &key, &nonce).unwrap();
    let decrypted = aead_open(algorithm, &encrypted, &aad, &key, &nonce).unwrap();
    assert_eq!(decrypted, msg);
}
