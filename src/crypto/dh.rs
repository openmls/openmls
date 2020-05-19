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

use crate::codec::*;
use crate::kp::*;
use rand::rngs::OsRng;
use sha2::*;
use std::fmt;
use std::hash::*;

// TODO replace secp256k1 by secp256r1

pub const X25519_PRIVATE_KEY_BYTES: usize = 32;
pub const X25519_PUBLIC_KEY_BYTES: usize = 32;
pub const X25519_SHARED_SECRET_BYTES: usize = 32;

pub const P256_PRIVATE_KEY_BYTES: usize = 32;
pub const P256_PUBLIC_KEY_BYTES: usize = 65;
pub const P256_SHARED_SECRET_BYTES: usize = 32;

pub const X448_PRIVATE_KEY_BYTES: usize = 56;
pub const X448_PUBLIC_KEY_BYTES: usize = 56;
pub const X448_SHARED_SECRET_BYTES: usize = 56;

pub const P521_PRIVATE_KEY_BYTES: usize = 66;
pub const P521_PUBLIC_KEY_BYTES: usize = 66;
pub const P521_SHARED_SECRET_BYTES: usize = 64;

#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum DHAlgorithm {
    X25519 = 1,
    P256 = 2,
    X448 = 3,
    P521 = 4,
    INVALID = 255,
}

impl From<u8> for DHAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            1 => DHAlgorithm::X25519,
            2 => DHAlgorithm::P256,
            3 => DHAlgorithm::X448,
            4 => DHAlgorithm::P521,
            _ => DHAlgorithm::INVALID,
        }
    }
}

impl From<CipherSuite> for DHAlgorithm {
    fn from(value: CipherSuite) -> Self {
        match value {
            CipherSuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => DHAlgorithm::P256,
            CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => DHAlgorithm::X25519,
            CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                DHAlgorithm::X25519
            }
            CipherSuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => DHAlgorithm::P521,
            CipherSuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => DHAlgorithm::X448,
            CipherSuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => DHAlgorithm::X448,
            CipherSuite::Default => DHAlgorithm::INVALID,
        }
    }
}

impl Codec for DHAlgorithm {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(DHAlgorithm::from(u8::decode(cursor)?))
    }
}

#[derive(Debug)]
pub enum DHError {
    WrongKeySize,
    InvalidAlgorithm,
}

pub fn shared_secret_length(algorithm: DHAlgorithm) -> usize {
    match algorithm {
        DHAlgorithm::X25519 => 32,
        DHAlgorithm::P256 => 32,
        DHAlgorithm::X448 => 64,
        DHAlgorithm::P521 => 64,
        DHAlgorithm::INVALID => panic!("Invalid DH algorithm"),
    }
}

#[derive(Debug, Clone, PartialEq)]
enum DHPublicKeyType {
    X25519(X25519PublicKey),
    P256(P256PublicKey),
}

impl Codec for DHPublicKeyType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            DHPublicKeyType::X25519(key) => {
                let algorithm = DHAlgorithm::X25519;
                algorithm.encode(buffer)?;
                key.encode(buffer)
            }
            DHPublicKeyType::P256(key) => {
                let algorithm = DHAlgorithm::P256;
                algorithm.encode(buffer)?;
                key.encode(buffer)
            }
        }
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let algorithm = DHAlgorithm::decode(cursor)?;
        match algorithm {
            DHAlgorithm::X25519 => {
                let key = X25519PublicKey::decode(cursor)?;
                Ok(DHPublicKeyType::X25519(key))
            }
            DHAlgorithm::P256 => {
                let key = P256PublicKey::decode(cursor)?;
                Ok(DHPublicKeyType::P256(key))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct DHPublicKey {
    key: DHPublicKeyType,
}

impl DHPublicKey {
    pub fn from_slice(bytes: &[u8], algorithm: DHAlgorithm) -> Result<DHPublicKey, DHError> {
        match algorithm {
            DHAlgorithm::X25519 => {
                let public_key = X25519PublicKey::from_slice(bytes)?;
                Ok(DHPublicKey {
                    key: DHPublicKeyType::X25519(public_key),
                })
            }
            DHAlgorithm::P256 => {
                let public_key = P256PublicKey::from_slice(bytes)?;
                Ok(DHPublicKey {
                    key: DHPublicKeyType::P256(public_key),
                })
            }
            _ => Err(DHError::InvalidAlgorithm),
        }
    }
    pub fn as_slice(&self) -> Vec<u8> {
        match &self.key {
            DHPublicKeyType::X25519(key) => key.as_slice(),
            DHPublicKeyType::P256(key) => key.as_slice(),
        }
    }
}

impl Codec for DHPublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key = DHPublicKeyType::decode(cursor)?;
        Ok(DHPublicKey { key })
    }
}

#[derive(Clone)]
enum DHPrivateKeyType {
    X25519(X25519PrivateKey),
    P256(P256PrivateKey),
}

impl Codec for DHPrivateKeyType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            DHPrivateKeyType::X25519(key) => {
                let algorithm = DHAlgorithm::X25519;
                algorithm.encode(buffer)?;
                key.encode(buffer)
            }
            DHPrivateKeyType::P256(key) => {
                let algorithm = DHAlgorithm::P256;
                algorithm.encode(buffer)?;
                key.encode(buffer)
            }
        }
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let algorithm = DHAlgorithm::decode(cursor)?;
        match algorithm {
            DHAlgorithm::X25519 => {
                let key = X25519PrivateKey::decode(cursor)?;
                Ok(DHPrivateKeyType::X25519(key))
            }
            DHAlgorithm::P256 => {
                let key = P256PrivateKey::decode(cursor)?;
                Ok(DHPrivateKeyType::P256(key))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Clone)]
pub struct DHPrivateKey {
    key: DHPrivateKeyType,
}

impl DHPrivateKey {
    pub fn new(algorithm: DHAlgorithm) -> Result<Self, DHError> {
        match algorithm {
            DHAlgorithm::X25519 => {
                let key = X25519PrivateKey::new();
                Ok(Self {
                    key: DHPrivateKeyType::X25519(key),
                })
            }
            DHAlgorithm::P256 => {
                let key = P256PrivateKey::new();
                Ok(Self {
                    key: DHPrivateKeyType::P256(key),
                })
            }
            _ => Err(DHError::InvalidAlgorithm),
        }
    }
    pub fn shared_secret(&self, dh_public_key: &DHPublicKey) -> Result<Vec<u8>, DHError> {
        match &self.key {
            DHPrivateKeyType::X25519(private_key) => match &dh_public_key.key {
                DHPublicKeyType::X25519(public_key) => Ok(private_key.shared_secret(&public_key)),
                DHPublicKeyType::P256(_) => Err(DHError::InvalidAlgorithm),
            },
            DHPrivateKeyType::P256(private_key) => match &dh_public_key.key {
                DHPublicKeyType::X25519(_) => Err(DHError::InvalidAlgorithm),
                DHPublicKeyType::P256(public_key) => Ok(private_key.shared_secret(&public_key)),
            },
        }
    }
    pub fn derive_public_key(&self) -> Result<DHPublicKey, DHError> {
        match &self.key {
            DHPrivateKeyType::X25519(private_key) => {
                let public_key = private_key.derive_public_key();
                Ok(DHPublicKey {
                    key: DHPublicKeyType::X25519(public_key),
                })
            }
            DHPrivateKeyType::P256(private_key) => {
                let public_key = private_key.derive_public_key();
                Ok(DHPublicKey {
                    key: DHPublicKeyType::P256(public_key),
                })
            }
        }
    }
    pub fn from_slice(bytes: &[u8], algorithm: DHAlgorithm) -> Result<DHPrivateKey, DHError> {
        match algorithm {
            DHAlgorithm::X25519 => {
                let private_key = X25519PrivateKey::from_slice(bytes)?;
                Ok(DHPrivateKey {
                    key: DHPrivateKeyType::X25519(private_key),
                })
            }
            DHAlgorithm::P256 => {
                let private_key = P256PrivateKey::from_slice(bytes)?;
                Ok(DHPrivateKey {
                    key: DHPrivateKeyType::P256(private_key),
                })
            }
            _ => Err(DHError::InvalidAlgorithm),
        }
    }
    pub fn as_slice(&self) -> Vec<u8> {
        match &self.key {
            DHPrivateKeyType::X25519(key) => key.as_slice(),
            DHPrivateKeyType::P256(key) => key.as_slice(),
        }
    }
}

impl fmt::Debug for DHPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<DHPrivateKey>")
    }
}

impl Codec for DHPrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key = DHPrivateKeyType::decode(cursor)?;
        Ok(DHPrivateKey { key })
    }
}

#[derive(Debug, Clone)]
pub struct DHKeyPair {
    pub private_key: DHPrivateKey,
    pub public_key: DHPublicKey,
}

impl DHKeyPair {
    pub fn new(algorithm: DHAlgorithm) -> Result<DHKeyPair, DHError> {
        let private_key = DHPrivateKey::new(algorithm)?;
        let public_key = private_key.derive_public_key()?;
        Ok(DHKeyPair {
            private_key,
            public_key,
        })
    }
    pub fn from_slice(bytes: &[u8], algorithm: DHAlgorithm) -> Result<Self, DHError> {
        let private_key = DHPrivateKey::from_slice(bytes, algorithm)?;
        Ok(DHKeyPair::from_private_key(&private_key))
    }
    pub fn from_private_key(private_key: &DHPrivateKey) -> DHKeyPair {
        DHKeyPair {
            private_key: private_key.clone(),
            public_key: private_key.derive_public_key().unwrap(),
        }
    }
}

impl Codec for DHKeyPair {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.private_key.encode(buffer)?;
        self.public_key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let private_key = DHPrivateKey::decode(cursor)?;
        let public_key = DHPublicKey::decode(cursor)?;
        Ok(DHKeyPair {
            private_key,
            public_key,
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct X25519PublicKey {
    key: x25519_dalek::PublicKey,
}

impl X25519PublicKey {
    pub fn from_slice(bytes: &[u8]) -> Result<X25519PublicKey, DHError> {
        if bytes.len() != X25519_PUBLIC_KEY_BYTES {
            return Err(DHError::WrongKeySize);
        }
        let mut value = [0u8; X25519_PUBLIC_KEY_BYTES];
        value.copy_from_slice(&bytes[..X25519_PUBLIC_KEY_BYTES]);
        Ok(X25519PublicKey {
            key: x25519_dalek::PublicKey::from(value),
        })
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.key.as_bytes().to_vec()
    }
}

impl PartialEq for X25519PublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.key.as_bytes() == other.key.as_bytes()
    }
}

impl Hash for X25519PublicKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.key.as_bytes().hash(state);
    }
}

impl Codec for X25519PublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, self.key.as_bytes())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_bytes = decode_vec(VecSize::VecU8, cursor)?;
        match X25519PublicKey::from_slice(&key_bytes) {
            Ok(public_key) => Ok(X25519PublicKey {
                key: public_key.key,
            }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Clone)]
struct X25519PrivateKey {
    key: x25519_dalek::StaticSecret,
}

impl X25519PrivateKey {
    pub fn new() -> Self {
        let mut csprng = OsRng {};
        let secret = x25519_dalek::StaticSecret::new(&mut csprng);
        Self { key: secret }
    }
    pub fn shared_secret(&self, public_key: &X25519PublicKey) -> Vec<u8> {
        let shared_secret = self.key.diffie_hellman(&public_key.key);
        shared_secret.as_bytes().to_vec()
    }
    pub fn derive_public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            key: x25519_dalek::PublicKey::from(&self.key),
        }
    }
    pub fn from_slice(bytes: &[u8]) -> Result<X25519PrivateKey, DHError> {
        if bytes.len() != X25519_PRIVATE_KEY_BYTES {
            return Err(DHError::WrongKeySize);
        }
        let mut value = [0u8; X25519_PRIVATE_KEY_BYTES];
        value.copy_from_slice(&bytes[..X25519_PRIVATE_KEY_BYTES]);
        Ok(X25519PrivateKey {
            key: x25519_dalek::StaticSecret::from(value),
        })
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }
}

impl Codec for X25519PrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.as_slice())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_bytes = decode_vec(VecSize::VecU8, cursor)?;
        match X25519PrivateKey::from_slice(&key_bytes) {
            Ok(private_key) => Ok(X25519PrivateKey {
                key: private_key.key,
            }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct P256PublicKey {
    key: secp256k1::PublicKey,
}

impl P256PublicKey {
    pub fn from_slice(bytes: &[u8]) -> Result<P256PublicKey, DHError> {
        if bytes.len() != P256_PUBLIC_KEY_BYTES {
            return Err(DHError::WrongKeySize);
        }
        match secp256k1::PublicKey::parse_slice(bytes, Some(secp256k1::PublicKeyFormat::Full)) {
            Ok(public_key) => Ok(P256PublicKey { key: public_key }),
            Err(_) => Err(DHError::WrongKeySize),
        }
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.key.serialize().to_vec()
    }
}

impl Codec for P256PublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.key.serialize())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_bytes = decode_vec(VecSize::VecU8, cursor)?;
        match P256PublicKey::from_slice(&key_bytes) {
            Ok(public_key) => Ok(P256PublicKey {
                key: public_key.key,
            }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Clone, Default)]
pub struct P256PrivateKey {
    key: secp256k1::SecretKey,
}

impl P256PrivateKey {
    pub fn new() -> Self {
        let mut csprng = OsRng {};
        let secret = secp256k1::SecretKey::random(&mut csprng);
        Self { key: secret }
    }
    pub fn shared_secret(&self, public_key: &P256PublicKey) -> Vec<u8> {
        let shared_secret =
            secp256k1::SharedSecret::<Sha256>::new(&public_key.key, &self.key).unwrap();
        shared_secret.as_ref().to_vec()
    }
    pub fn derive_public_key(&self) -> P256PublicKey {
        P256PublicKey {
            key: secp256k1::PublicKey::from_secret_key(&self.key),
        }
    }
    pub fn from_slice(bytes: &[u8]) -> Result<P256PrivateKey, DHError> {
        if bytes.len() != P256_PRIVATE_KEY_BYTES {
            return Err(DHError::WrongKeySize);
        }
        match secp256k1::SecretKey::parse_slice(bytes) {
            Ok(private_key) => Ok(P256PrivateKey { key: private_key }),
            Err(_) => Err(DHError::WrongKeySize),
        }
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.key.serialize().to_vec()
    }
}

impl Codec for P256PrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU8, buffer, &self.key.serialize())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_bytes = decode_vec(VecSize::VecU8, cursor)?;
        match P256PrivateKey::from_slice(&key_bytes) {
            Ok(public_key) => Ok(P256PrivateKey {
                key: public_key.key,
            }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

pub struct P256KeyPair {
    pub private_key: P256PrivateKey,
    pub public_key: P256PublicKey,
}

impl P256KeyPair {
    pub fn from_slice(bytes: &[u8]) -> Result<Self, DHError> {
        let private_key = P256PrivateKey::from_slice(bytes)?;
        Ok(P256KeyPair::from_private_key(&private_key))
    }
    pub fn from_private_key(private_key: &P256PrivateKey) -> P256KeyPair {
        P256KeyPair {
            private_key: private_key.clone(),
            public_key: private_key.derive_public_key(),
        }
    }
}

impl Default for P256KeyPair {
    fn default() -> Self {
        let private_key = P256PrivateKey::new();
        let public_key = private_key.derive_public_key();
        P256KeyPair {
            private_key,
            public_key,
        }
    }
}
