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
use crate::utils::*;
use evercrypt::prelude::*;
use hpke::*;

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Name {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
}

impl From<&Name> for u16 {
    fn from(s: &Name) -> u16 {
        *s as u16
    }
}

impl From<u16> for Name {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            0x0002 => Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
            0x0003 => Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            0x0004 => Name::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            0x0005 => Name::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521,
            0x0006 => Name::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            _ => panic!("Not implemented."),
        }
    }
}

impl Codec for Name {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        u16::from(self).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(Name::from(u16::decode(cursor)?))
    }
}

fn get_hash_from_suite(name: &Name) -> DigestMode {
    match name {
        Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => DigestMode::Sha256,
        Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => DigestMode::Sha256,
        Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => DigestMode::Sha256,
        Name::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => DigestMode::Sha512,
        Name::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => DigestMode::Sha512,
        Name::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => DigestMode::Sha512,
    }
}

fn get_aead_from_suite(name: &Name) -> AeadMode {
    match name {
        Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => AeadMode::Aes128Gcm,
        Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => AeadMode::Aes128Gcm,
        Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => AeadMode::Chacha20Poly1305,
        Name::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => AeadMode::Aes256Gcm,
        Name::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => AeadMode::Aes256Gcm,
        Name::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => AeadMode::Chacha20Poly1305,
    }
}

fn get_signature_from_suite(name: &Name) -> SignatureMode {
    match name {
        Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => SignatureMode::Ed25519,
        Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => SignatureMode::P256,
        Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => SignatureMode::Ed25519,
        _ => panic!(
            "Signature scheme for ciphersuite {:?} is not implemented yet.",
            name
        ),
    }
}

fn get_kem_from_suite(name: &Name) -> hpke::kem::Mode {
    match name {
        Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => hpke::kem::Mode::DhKem25519,
        Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => hpke::kem::Mode::DhKemP256,
        Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => hpke::kem::Mode::DhKem25519,
        _ => panic!("KEM for ciphersuite {:?} is not implemented yet.", name),
    }
}

fn get_kdf_from_suite(name: &Name) -> HmacMode {
    match name {
        Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
        | Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => HmacMode::Sha256,
        Name::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Name::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
        | Name::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HmacMode::Sha512,
    }
}

fn get_hpke_kdf_from_suite(name: &Name) -> hpke::kdf::Mode {
    match name {
        Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
        | Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            hpke::kdf::Mode::HkdfSha256
        }
        Name::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | Name::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
        | Name::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => hpke::kdf::Mode::HkdfSha512,
    }
}

fn get_hpke_aead_from_suite(name: &Name) -> hpke::aead::Mode {
    match name {
        Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => hpke::aead::Mode::AesGcm128,
        Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => hpke::aead::Mode::AesGcm128,
        Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            hpke::aead::Mode::ChaCha20Poly1305
        }
        Name::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => hpke::aead::Mode::AesGcm256,
        Name::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => hpke::aead::Mode::AesGcm256,
        Name::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            hpke::aead::Mode::ChaCha20Poly1305
        }
    }
}

#[derive(Debug)]
pub enum HKDFError {
    InvalidLength,
}

#[derive(PartialEq, Copy, Clone, Debug)]
pub struct Ciphersuite {
    pub name: Name,
}

#[derive(Debug, PartialEq, Clone)]
pub struct HpkeCiphertext {
    pub kem_output: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Codec for HpkeCiphertext {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.kem_output)?;
        encode_vec(VecSize::VecU16, buffer, &self.ciphertext)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let kem_output = decode_vec(VecSize::VecU16, cursor)?;
        let ciphertext = decode_vec(VecSize::VecU16, cursor)?;
        Ok(HpkeCiphertext {
            kem_output,
            ciphertext,
        })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEPublicKey(Vec<u8>);

impl HPKEPublicKey {
    pub fn as_slice(&self) -> Vec<u8> {
        self.0.clone()
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
}

impl Codec for HPKEPublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.0)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self(inner))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEPrivateKey(Vec<u8>);

impl HPKEPrivateKey {
    pub fn as_slice(&self) -> Vec<u8> {
        self.0.clone()
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }
    pub fn public_key(&self) -> HPKEPublicKey {
        // TODO: add agility
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&self.0);
        let pk = x25519_base(&sk);
        HPKEPublicKey::from_slice(&pk)
    }
}

impl Codec for HPKEPrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.0)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let inner = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self(inner))
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct HPKEKeyPair {
    pub private_key: HPKEPrivateKey,
    pub public_key: HPKEPublicKey,
}

impl HPKEKeyPair {
    pub fn from_slice(bytes: &[u8]) -> Self {
        let private_key = HPKEPrivateKey::from_slice(bytes);
        let public_key = private_key.public_key();
        Self {
            private_key,
            public_key,
        }
    }
}

impl Codec for HPKEKeyPair {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.private_key.encode(buffer)?;
        self.public_key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let public_key = HPKEPublicKey::decode(cursor)?;
        let private_key = HPKEPrivateKey::decode(cursor)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }
}

pub type DHPublicKey2 = [u8];
pub type DHPrivateKey2 = [u8];

pub const NONCEBYTES: usize = 12;
pub const CHACHAKEYBYTES: usize = 32;
pub const AES128KEYBYTES: usize = 16;
pub const AES256KEYBYTES: usize = 32;
pub const TAGBYTES: usize = 16;

#[derive(Debug)]
pub enum AEADError {
    EncryptionError,
    DecryptionError,
    WrongKeyLength,
}

#[derive(Debug, PartialEq)]
pub struct AEADKey {
    value: Vec<u8>,
}

impl AEADKey {
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
}

#[derive(PartialEq, Debug)]
pub struct Nonce([u8; NONCEBYTES]);

impl Nonce {
    pub fn new_random() -> Nonce {
        let random_bytes = randombytes(NONCEBYTES);
        let mut bytes: [u8; NONCEBYTES] = [0u8; NONCEBYTES];
        bytes[..NONCEBYTES].clone_from_slice(&random_bytes[..NONCEBYTES]);
        Nonce(bytes)
    }

    pub fn as_slice(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct Signature {
    value: Vec<u8>,
}

impl Signature {
    pub fn new_empty() -> Signature {
        Signature { value: vec![] }
    }
    pub fn as_slice(&self) -> Vec<u8> {
        self.value.clone()
    }
}

impl Codec for Signature {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self { value })
    }
}

#[derive(Clone)]
pub struct SignaturePrivateKey {
    pub value: Vec<u8>,
}

impl Codec for SignaturePrivateKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self { value })
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct SignaturePublicKey {
    pub value: Vec<u8>,
}

impl Codec for SignaturePublicKey {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        encode_vec(VecSize::VecU16, buffer, &self.value)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let value = decode_vec(VecSize::VecU16, cursor)?;
        Ok(Self { value })
    }
}

#[derive(Clone)]
pub struct SignatureKeypair {
    pub ciphersuite: Ciphersuite,
    pub private_key: SignaturePrivateKey,
    pub public_key: SignaturePublicKey,
}

impl SignatureKeypair {
    pub fn sign(&self, payload: &[u8]) -> Signature {
        self.ciphersuite.sign(&self.private_key, payload)
    }
}

impl Codec for SignatureKeypair {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.ciphersuite.encode(buffer)?;
        self.private_key.encode(buffer)?;
        self.public_key.encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let ciphersuite = Ciphersuite::decode(cursor)?;
        let private_key = SignaturePrivateKey::decode(cursor)?;
        let public_key = SignaturePublicKey::decode(cursor)?;
        Ok(Self {
            ciphersuite,
            private_key,
            public_key,
        })
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

impl Ciphersuite {
    pub fn new(name: Name) -> Self {
        Ciphersuite { name }
    }
    pub fn sign(&self, sk: &SignaturePrivateKey, msg: &[u8]) -> Signature {
        // TODO: add agility
        let signature_mode = get_signature_from_suite(&self.name);
        if signature_mode != SignatureMode::Ed25519 {
            panic!("Only ed25519 is currently supported");
        }
        Signature {
            value: sign(signature_mode, None, &sk.value, msg, None).unwrap(),
        }
    }
    pub fn verify(&self, sig: &Signature, pk: &SignaturePublicKey, msg: &[u8]) -> bool {
        // TODO: add agility
        let signature_mode = get_signature_from_suite(&self.name);
        if signature_mode != SignatureMode::Ed25519 {
            panic!("Only ed25519 is currently supported");
        }
        verify(signature_mode, None, &pk.value, &sig.value, msg).unwrap()
    }
    pub fn new_signature_keypair(&self) -> SignatureKeypair {
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
    pub fn hash(&self, payload: &[u8]) -> Vec<u8> {
        hash(get_hash_from_suite(&self.name), payload)
    }
    pub fn hash_length(&self) -> usize {
        match get_hash_from_suite(&self.name) {
            DigestMode::Sha256 => 32,
            DigestMode::Sha512 => 64,
            _ => 0,
        }
    }
    pub fn hmac(&self, key: &[u8], data: &[u8]) -> Vec<u8> {
        hmac(get_kdf_from_suite(&self.name), key, data, None)
    }
    pub fn hkdf(
        &self,
        salt: &[u8],
        ikm: &[u8],
        info: &[u8],
        okm_len: usize,
    ) -> Result<Vec<u8>, HKDFError> {
        // TODO: error handling
        Ok(hkdf(
            get_kdf_from_suite(&self.name),
            salt,
            ikm,
            info,
            okm_len,
        ))
    }
    pub fn hkdf_extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        hkdf_extract(get_kdf_from_suite(&self.name), salt, ikm)
    }
    pub fn hkdf_expand(
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
    pub fn hkdf_expand_label() {
        // TODO: implement
    }

    pub fn aead_seal(
        &self,
        msg: &[u8],
        aad: &[u8],
        key: &AEADKey,
        nonce: &Nonce,
    ) -> Result<Vec<u8>, AEADError> {
        let (ct, tag) = match aead_encrypt(
            get_aead_from_suite(&self.name),
            &key.as_slice(),
            msg,
            &nonce.0,
            aad,
        ) {
            Ok((ct, tag)) => (ct, tag),
            Err(_) => return Err(AEADError::EncryptionError),
        };
        let mut ciphertext = ct;
        ciphertext.extend_from_slice(&tag);
        Ok(ciphertext)
    }
    pub fn aead_open(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        key: &AEADKey,
        nonce: &Nonce,
    ) -> Result<Vec<u8>, AEADError> {
        if ciphertext.len() < TAGBYTES {
            return Err(AEADError::DecryptionError);
        }
        let payload = ciphertext.to_vec();
        let (ct, tag) = payload.split_at(ciphertext.len() - TAGBYTES);
        match aead_decrypt(
            get_aead_from_suite(&self.name),
            &key.as_slice(),
            ct,
            tag,
            &nonce.0,
            aad,
        ) {
            Ok(pt) => Ok(pt),
            Err(_) => Err(AEADError::DecryptionError),
        }
    }

    pub fn new_aead_key(&self, bytes: &[u8]) -> Result<AEADKey, AEADError> {
        if bytes.len() != self.aead_key_length() {
            Err(AEADError::WrongKeyLength)
        } else {
            Ok(AEADKey {
                value: bytes.to_vec(),
            })
        }
    }

    pub fn aead_key_length(&self) -> usize {
        match get_aead_from_suite(&self.name) {
            AeadMode::Aes128Gcm => AES128KEYBYTES,
            AeadMode::Aes256Gcm => AES256KEYBYTES,
            AeadMode::Chacha20Poly1305 => CHACHAKEYBYTES,
        }
    }

    pub fn new_aead_nonce(&self, bytes: &[u8]) -> Result<Nonce, AEADError> {
        if bytes.len() != NONCEBYTES {
            return Err(AEADError::WrongKeyLength);
        }
        let mut value = [0u8; NONCEBYTES];
        value.copy_from_slice(bytes);
        Ok(Nonce(value))
    }

    pub fn new_aead_nonce_random(&self) -> Nonce {
        self.new_aead_nonce(&randombytes(NONCEBYTES)).unwrap()
    }

    pub fn aead_nonce_length(&self) -> usize {
        NONCEBYTES
    }

    pub fn hpke_seal(
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
    pub fn hpke_open(
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
    pub fn new_hpke_keypair(&self) -> HPKEKeyPair {
        // TODO: add agility
        match get_kem_from_suite(&self.name) {
            kem::Mode::DhKem25519 => HPKEKeyPair::from_slice(&randombytes(32)),
            _ => unimplemented!(),
        }
    }
}

impl From<Name> for Ciphersuite {
    fn from(v: Name) -> Self {
        Self::new(v)
    }
}

impl Codec for Ciphersuite {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        (self.name as u16).encode(buffer)?;
        Ok(())
    }
    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        Ok(Ciphersuite::new(Name::from(u16::decode(cursor)?)))
    }
}

#[test]
fn test_hpke() {
    let csuite = Ciphersuite::new(Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

    let aad = b"additional info";
    let ptxt = b"plaintext";
    let info = b"info";
    let sk_r = [
        0xc8, 0xa9, 0xd5, 0xa9, 0x10, 0x91, 0xad, 0x85, 0x1c, 0x66, 0x8b, 0x07, 0x36, 0xc1, 0xc9,
        0xa0, 0x29, 0x36, 0xc0, 0xd3, 0xad, 0x62, 0x67, 0x08, 0x58, 0x08, 0x80, 0x47, 0xba, 0x05,
        0x74, 0x75,
    ];
    let pk_r = x25519_base(&sk_r);

    let sealed = csuite.hpke_seal(&HPKEPublicKey::from_slice(&pk_r), info, aad, ptxt);
    let _ptxt_out = csuite.hpke_open(sealed, &HPKEPrivateKey::from_slice(&sk_r), info, aad);
}
