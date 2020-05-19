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
use crate::creds::*;
use crate::crypto::hash::*;
use crate::kp::*;
use ed25519_dalek;
use rand::rngs::OsRng;

// TODO replace secp256k1 by secp256r1

#[derive(Debug)]
pub enum SignatureError {
    InvalidAlgorithm,
    WrongKeyLength,
}

#[derive(PartialEq, Clone, Copy, Debug)]
#[repr(u8)]
pub enum SignatureAlgorithm {
    Ed25519 = 1,
    P256 = 2,
    Ed448 = 3,
    P521 = 4,
    INVALID = 255,
}

impl From<u8> for SignatureAlgorithm {
    fn from(value: u8) -> Self {
        match value {
            1 => SignatureAlgorithm::Ed25519,
            2 => SignatureAlgorithm::P256,
            3 => SignatureAlgorithm::Ed448,
            4 => SignatureAlgorithm::P521,
            _ => SignatureAlgorithm::INVALID,
        }
    }
}

impl From<CipherSuite> for SignatureAlgorithm {
    fn from(value: CipherSuite) -> Self {
        match value {
            CipherSuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => SignatureAlgorithm::P256,
            CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => {
                SignatureAlgorithm::Ed25519
            }
            CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                SignatureAlgorithm::Ed25519
            }
            CipherSuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => SignatureAlgorithm::P521,
            CipherSuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => SignatureAlgorithm::Ed448,
            CipherSuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => {
                SignatureAlgorithm::Ed448
            }
            CipherSuite::Default => SignatureAlgorithm::INVALID,
        }
    }
}

impl Codec for SignatureAlgorithm {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (*self as u8).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(SignatureAlgorithm::from(u8::decode(cursor)?))
    }
}

pub trait Signable: Sized {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError>;

    fn sign(&mut self, id: &Identity) -> Signature {
        let payload = self.unsigned_payload().unwrap();
        id.sign(&payload)
    }
    fn verify(&self, id: &Identity, signature: &Signature) -> bool {
        let payload = self.unsigned_payload().unwrap();
        id.verify(&payload, signature)
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SignaturePublicKeyType {
    Ed25519(Ed25519PublicKey),
    P256(P256PublicKey),
}

impl Codec for SignaturePublicKeyType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            SignaturePublicKeyType::Ed25519(key) => {
                let algorithm = SignatureAlgorithm::Ed25519;
                algorithm.encode(buffer)?;
                key.encode(buffer)?;
            }
            SignaturePublicKeyType::P256(key) => {
                let algorithm = SignatureAlgorithm::P256;
                algorithm.encode(buffer)?;
                key.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let algorithm = SignatureAlgorithm::decode(cursor)?;
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let key = Ed25519PublicKey::decode(cursor)?;
                Ok(SignaturePublicKeyType::Ed25519(key))
            }
            SignatureAlgorithm::P256 => {
                let key = P256PublicKey::decode(cursor)?;
                Ok(SignaturePublicKeyType::P256(key))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}
#[derive(Debug)]
enum SignaturePrivateKeyType {
    Ed25519(Ed25519PrivateKey),
    P256(P256PrivateKey),
}

impl Codec for SignaturePrivateKeyType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            SignaturePrivateKeyType::Ed25519(key) => {
                let algorithm = SignatureAlgorithm::Ed25519;
                algorithm.encode(buffer)?;
                key.encode(buffer)?;
            }
            SignaturePrivateKeyType::P256(key) => {
                let algorithm = SignatureAlgorithm::P256;
                algorithm.encode(buffer)?;
                key.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let algorithm = SignatureAlgorithm::decode(cursor)?;
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let key = Ed25519PrivateKey::decode(cursor)?;
                Ok(SignaturePrivateKeyType::Ed25519(key))
            }
            SignatureAlgorithm::P256 => {
                let key = P256PrivateKey::decode(cursor)?;
                Ok(SignaturePrivateKeyType::P256(key))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug)]
enum SignatureKeypairType {
    Ed25519(Ed25519Keypair),
    P256(P256Keypair),
}

impl Codec for SignatureKeypairType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            SignatureKeypairType::Ed25519(key) => {
                let algorithm = SignatureAlgorithm::Ed25519;
                algorithm.encode(buffer)?;
                key.encode(buffer)?;
            }
            SignatureKeypairType::P256(key) => {
                let algorithm = SignatureAlgorithm::P256;
                algorithm.encode(buffer)?;
                key.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let algorithm = SignatureAlgorithm::decode(cursor)?;
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let key = Ed25519Keypair::decode(cursor)?;
                Ok(SignatureKeypairType::Ed25519(key))
            }
            SignatureAlgorithm::P256 => {
                let key = P256Keypair::decode(cursor)?;
                Ok(SignatureKeypairType::P256(key))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum SignatureType {
    Ed25519(Ed25519Signature),
    P256(P256Signature),
    Invalid,
}

impl Codec for SignatureType {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match self {
            SignatureType::Ed25519(value) => {
                let algorithm = SignatureAlgorithm::Ed25519;
                algorithm.encode(buffer)?;
                value.encode(buffer)?;
            }
            SignatureType::P256(value) => {
                let algorithm = SignatureAlgorithm::P256;
                algorithm.encode(buffer)?;
                value.encode(buffer)?;
            }
            _ => (),
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let algorithm = SignatureAlgorithm::decode(cursor)?;
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let value = Ed25519Signature::decode(cursor)?;
                Ok(SignatureType::Ed25519(value))
            }
            SignatureAlgorithm::P256 => {
                let value = P256Signature::decode(cursor)?;
                Ok(SignatureType::P256(value))
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SignaturePublicKey {
    key: SignaturePublicKeyType,
}

impl SignaturePublicKey {
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        match &self.key {
            SignaturePublicKeyType::Ed25519(key) => match &signature.signature {
                SignatureType::Ed25519(ed25519_signature) => {
                    key.verify(payload, &ed25519_signature)
                }
                _ => false,
            },
            SignaturePublicKeyType::P256(key) => match &signature.signature {
                SignatureType::P256(p256_signature) => key.verify(payload, &p256_signature),
                _ => false,
            },
        }
    }
    pub fn from_bytes(algorithm: SignatureAlgorithm, bytes: &[u8]) -> Result<Self, SignatureError> {
        match algorithm {
            SignatureAlgorithm::Ed25519 => match Ed25519PublicKey::from_bytes(bytes) {
                Ok(key) => Ok(SignaturePublicKey {
                    key: SignaturePublicKeyType::Ed25519(key),
                }),
                Err(err) => Err(err),
            },
            SignatureAlgorithm::P256 => match P256PublicKey::from_bytes(bytes) {
                Ok(key) => Ok(SignaturePublicKey {
                    key: SignaturePublicKeyType::P256(key),
                }),
                Err(err) => Err(err),
            },
            _ => Err(SignatureError::InvalidAlgorithm),
        }
    }
}

impl Codec for SignaturePublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key = SignaturePublicKeyType::decode(cursor)?;
        Ok(SignaturePublicKey { key })
    }
}

pub struct SignaturePrivateKey {
    key: SignaturePrivateKeyType,
}

impl Codec for SignaturePrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key = SignaturePrivateKeyType::decode(cursor)?;
        Ok(SignaturePrivateKey { key })
    }
}

pub struct SignatureKeypair {
    keypair: SignatureKeypairType,
}

impl SignatureKeypair {
    pub fn new(algorithm: SignatureAlgorithm) -> Result<Self, SignatureError> {
        match algorithm {
            SignatureAlgorithm::Ed25519 => Ok(Self {
                keypair: SignatureKeypairType::Ed25519(Ed25519Keypair::new()),
            }),
            SignatureAlgorithm::P256 => Ok(Self {
                keypair: SignatureKeypairType::P256(P256Keypair::new()),
            }),
            _ => Err(SignatureError::InvalidAlgorithm),
        }
    }
    pub fn sign(&self, payload: &[u8]) -> Signature {
        match &self.keypair {
            SignatureKeypairType::Ed25519(keypair) => {
                let signature = keypair.sign(payload);
                Signature {
                    signature: SignatureType::Ed25519(signature),
                }
            }
            SignatureKeypairType::P256(keypair) => {
                let signature = keypair.sign(payload);
                Signature {
                    signature: SignatureType::P256(signature),
                }
            }
        }
    }
    pub fn verify(&self, payload: &[u8], signature: &Signature) -> bool {
        match &self.keypair {
            SignatureKeypairType::Ed25519(keypair) => match &signature.signature {
                SignatureType::Ed25519(ed25519_signature) => {
                    keypair.verify(payload, &ed25519_signature)
                }
                _ => false,
            },
            SignatureKeypairType::P256(keypair) => match &signature.signature {
                SignatureType::P256(p256_signature) => keypair.verify(payload, &p256_signature),
                _ => false,
            },
        }
    }
    pub fn get_public_key(&self) -> SignaturePublicKey {
        match &self.keypair {
            SignatureKeypairType::Ed25519(keypair) => SignaturePublicKey {
                key: SignaturePublicKeyType::Ed25519(keypair.get_public_key()),
            },
            SignatureKeypairType::P256(keypair) => SignaturePublicKey {
                key: SignaturePublicKeyType::P256(keypair.get_public_key()),
            },
        }
    }
}

impl Codec for SignatureKeypair {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.keypair {
            SignatureKeypairType::Ed25519(keypair) => {
                let algorithm = SignatureAlgorithm::Ed25519;
                algorithm.encode(buffer)?;
                keypair.encode(buffer)?;
            }
            SignatureKeypairType::P256(keypair) => {
                let algorithm = SignatureAlgorithm::P256;
                algorithm.encode(buffer)?;
                keypair.encode(buffer)?;
            }
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let algorithm = SignatureAlgorithm::decode(cursor)?;
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let keypair = Ed25519Keypair::decode(cursor)?;
                Ok(SignatureKeypair {
                    keypair: SignatureKeypairType::Ed25519(keypair),
                })
            }
            SignatureAlgorithm::P256 => {
                let keypair = P256Keypair::decode(cursor)?;
                Ok(SignatureKeypair {
                    keypair: SignatureKeypairType::P256(keypair),
                })
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Signature {
    signature: SignatureType,
}

impl Signature {
    pub fn new_empty() -> Self {
        Self {
            signature: SignatureType::Invalid,
        }
    }
    pub fn from_bytes(algorithm: SignatureAlgorithm, bytes: &[u8]) -> Result<Self, SignatureError> {
        match algorithm {
            SignatureAlgorithm::Ed25519 => match Ed25519Signature::from_bytes(bytes) {
                Ok(signature) => Ok(Signature {
                    signature: SignatureType::Ed25519(signature),
                }),
                Err(err) => Err(err),
            },
            SignatureAlgorithm::P256 => match P256Signature::from_bytes(bytes) {
                Ok(signature) => Ok(Signature {
                    signature: SignatureType::P256(signature),
                }),
                Err(err) => Err(err),
            },
            _ => Err(SignatureError::InvalidAlgorithm),
        }
    }
    pub fn to_bytes(&self) -> Result<Vec<u8>, SignatureError> {
        match &self.signature {
            SignatureType::Ed25519(signature) => Ok(signature.to_bytes()),
            SignatureType::P256(signature) => Ok(signature.to_bytes()),
            _ => Err(SignatureError::InvalidAlgorithm),
        }
    }
}

impl Codec for Signature {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        match &self.signature {
            SignatureType::Ed25519(signature) => {
                let algorithm = SignatureAlgorithm::Ed25519;
                algorithm.encode(buffer)?;
                signature.encode(buffer)?;
            }
            SignatureType::P256(signature) => {
                let algorithm = SignatureAlgorithm::P256;
                algorithm.encode(buffer)?;
                signature.encode(buffer)?;
            }
            _ => (),
        }
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let algorithm = SignatureAlgorithm::decode(cursor)?;
        match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let signature = Ed25519Signature::decode(cursor)?;
                Ok(Signature {
                    signature: SignatureType::Ed25519(signature),
                })
            }
            SignatureAlgorithm::P256 => {
                let signature = P256Signature::decode(cursor)?;
                Ok(Signature {
                    signature: SignatureType::P256(signature),
                })
            }
            _ => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Ed25519PublicKey {
    key: ed25519_dalek::PublicKey,
}

impl Ed25519PublicKey {
    pub fn verify(&self, payload: &[u8], signature: &Ed25519Signature) -> bool {
        self.key.verify(payload, &signature.value).is_ok()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Ed25519PublicKey, SignatureError> {
        match ed25519_dalek::PublicKey::from_bytes(bytes) {
            Ok(key) => Ok(Ed25519PublicKey { key }),
            Err(_) => Err(SignatureError::WrongKeyLength),
        }
    }
}

impl Codec for Ed25519PublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.key.to_bytes())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_bytes = decode_vec(VecSize::VecU16, cursor)?;
        match ed25519_dalek::PublicKey::from_bytes(&key_bytes) {
            Ok(key) => Ok(Ed25519PublicKey { key }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug)]
struct Ed25519PrivateKey {
    key: ed25519_dalek::SecretKey,
}

impl Codec for Ed25519PrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.key.to_bytes())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_bytes = decode_vec(VecSize::VecU16, cursor)?;
        match ed25519_dalek::SecretKey::from_bytes(&key_bytes) {
            Ok(key) => Ok(Ed25519PrivateKey { key }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct Ed25519Signature {
    pub value: ed25519_dalek::Signature,
}

impl Ed25519Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        match ed25519_dalek::Signature::from_bytes(bytes) {
            Ok(signature) => Ok(Ed25519Signature { value: signature }),
            Err(_) => Err(SignatureError::WrongKeyLength),
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_bytes().to_vec()
    }
}

impl Codec for Ed25519Signature {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value.to_bytes())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value_bytes = decode_vec(VecSize::VecU16, cursor)?;
        match ed25519_dalek::Signature::from_bytes(&value_bytes) {
            Ok(value) => Ok(Ed25519Signature { value }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug)]
struct Ed25519Keypair {
    keypair: ed25519_dalek::Keypair,
}

impl Ed25519Keypair {
    pub fn new() -> Self {
        let mut csprng = OsRng {};
        Self {
            keypair: ed25519_dalek::Keypair::generate(&mut csprng),
        }
    }
    pub fn sign(&self, payload: &[u8]) -> Ed25519Signature {
        Ed25519Signature {
            value: self.keypair.sign(payload),
        }
    }
    pub fn verify(&self, payload: &[u8], signature: &Ed25519Signature) -> bool {
        self.keypair.verify(payload, &signature.value).is_ok()
    }
    pub fn get_public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey {
            key: self.keypair.public,
        }
    }
}

impl Codec for Ed25519Keypair {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.keypair.to_bytes())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let keypair_bytes = decode_vec(VecSize::VecU16, cursor)?;
        match ed25519_dalek::Keypair::from_bytes(&keypair_bytes) {
            Ok(keypair) => Ok(Ed25519Keypair { keypair }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct P256PublicKey {
    key: secp256k1::PublicKey,
}

impl P256PublicKey {
    pub fn verify(&self, payload: &[u8], signature: &P256Signature) -> bool {
        let hashed_payload = hash(HashAlgorithm::SHA256, payload);
        let message_option = secp256k1::Message::parse_slice(&hashed_payload);
        match message_option {
            Ok(message) => secp256k1::verify(&message, &signature.value, &self.key),
            Err(_) => false,
        }
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<P256PublicKey, SignatureError> {
        match secp256k1::PublicKey::parse_slice(bytes, Some(secp256k1::PublicKeyFormat::Full)) {
            Ok(key) => Ok(P256PublicKey { key }),
            Err(_) => Err(SignatureError::WrongKeyLength),
        }
    }
}

impl Codec for P256PublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.key.serialize())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_bytes = decode_vec(VecSize::VecU16, cursor)?;
        match secp256k1::PublicKey::parse_slice(&key_bytes, Some(secp256k1::PublicKeyFormat::Full))
        {
            Ok(key) => Ok(P256PublicKey { key }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug)]
struct P256PrivateKey {
    key: secp256k1::SecretKey,
}

impl Codec for P256PrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.key.serialize())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_bytes = decode_vec(VecSize::VecU16, cursor)?;
        match secp256k1::SecretKey::parse_slice(&key_bytes) {
            Ok(key) => Ok(P256PrivateKey { key }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct P256Signature {
    pub value: secp256k1::Signature,
}

impl P256Signature {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignatureError> {
        match secp256k1::Signature::parse_slice(bytes) {
            Ok(signature) => Ok(P256Signature { value: signature }),
            Err(_) => Err(SignatureError::WrongKeyLength),
        }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.serialize().to_vec()
    }
}

impl Codec for P256Signature {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value.serialize())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value_bytes = decode_vec(VecSize::VecU16, cursor)?;
        match secp256k1::Signature::parse_slice(&value_bytes) {
            Ok(value) => Ok(P256Signature { value }),
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[derive(Debug)]
struct P256Keypair {
    secret_key: secp256k1::SecretKey,
    public_key: secp256k1::PublicKey,
}

impl P256Keypair {
    pub fn new() -> Self {
        let mut csprng = OsRng {};
        let secret_key = secp256k1::SecretKey::random(&mut csprng);
        let public_key = secp256k1::PublicKey::from_secret_key(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }
    pub fn sign(&self, payload: &[u8]) -> P256Signature {
        let hashed_payload = hash(HashAlgorithm::SHA256, payload);
        let message = secp256k1::Message::parse_slice(&hashed_payload).unwrap();
        let (value, _) = secp256k1::sign(&message, &self.secret_key);
        P256Signature { value }
    }
    pub fn verify(&self, payload: &[u8], signature: &P256Signature) -> bool {
        let hashed_payload = hash(HashAlgorithm::SHA256, payload);
        let message = secp256k1::Message::parse_slice(&hashed_payload).unwrap();
        secp256k1::verify(&message, &signature.value, &self.public_key)
    }
    pub fn get_public_key(&self) -> P256PublicKey {
        P256PublicKey {
            key: self.public_key.clone(),
        }
    }
}

impl Codec for P256Keypair {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.secret_key.serialize())?;
        encode_vec(VecSize::VecU16, buffer, &self.public_key.serialize())?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let secret_key_bytes = decode_vec(VecSize::VecU16, cursor)?;
        let public_key_bytes = decode_vec(VecSize::VecU16, cursor)?;
        match secp256k1::SecretKey::parse_slice(&secret_key_bytes) {
            Ok(secret_key) => {
                match secp256k1::PublicKey::parse_slice(
                    &public_key_bytes,
                    Some(secp256k1::PublicKeyFormat::Full),
                ) {
                    Ok(public_key) => Ok(P256Keypair {
                        secret_key,
                        public_key,
                    }),
                    Err(_) => Err(CodecError::DecodingError),
                }
            }
            Err(_) => Err(CodecError::DecodingError),
        }
    }
}

#[test]
fn test_signature() {
    use crate::utils::*;

    let payload = vec![0, 1, 2, 3];
    let pk = SignaturePublicKey::from_bytes(
        SignatureAlgorithm::Ed25519,
        &hex_to_bytes("6f8a35bff581235d8757b2f3cea6e6bfa7c5005852ac8ccf3c63a2c45c514d0d"),
    )
    .unwrap();
    let sig = Signature::from_bytes(SignatureAlgorithm::Ed25519, &hex_to_bytes("4d51569eb56fc808cad8d8707110bcbf5c3daae9d394af77d48e840b2750ab15ea04c0fd30658625a20d0446fbd8ae09c6cc67f1004ed8c79818b74bef4fa107")).unwrap();
    assert!(pk.verify(&payload, &sig));
}

#[test]
fn ed25519_codec() {
    let pk = Ed25519Keypair::new().get_public_key();
    let encoded = pk.encode_detached().unwrap();
    let decoded = Ed25519PublicKey::decode_detached(&encoded).unwrap();
    assert_eq!(pk, decoded);
}

/*
#[test]
fn p256_sign_verify() {
    let data = &[1, 2, 3];
    let key_pair = SignatureKeypair::new(SignatureAlgorithm::P256).unwrap();
    let sk = key_pair.private_key;
    let pk = key_pair.public_key;
    //let signature = sk.sign(data);
    //assert!(key_pair.verify(data, &signature));
}
*/
