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

pub struct Ciphersuite {
    name: Name,
}

type HpkeCiphertext2 = (Vec<u8>, Vec<u8>); // (kem_out, ctxt)
type DHPublicKey2 = [u8];
type DHPrivateKey2 = [u8];

impl Ciphersuite {
    pub fn new(name: Name) -> Self {
        Ciphersuite { name }
    }
    pub fn hash(&self, payload: &[u8]) {
        hash(get_hash_from_suite(&self.name), payload);
    }
    pub fn sign() {}
    pub fn verify() {}
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

    pub fn seal(
        &self,
        pk_r: &DHPublicKey2,
        info: &[u8],
        aad: &[u8],
        ptxt: &[u8],
    ) -> HpkeCiphertext2 {
        let hpke = Hpke::new(
            Mode::Base,
            get_kem_from_suite(&self.name),
            get_hpke_kdf_from_suite(&self.name),
            get_hpke_aead_from_suite(&self.name),
        );
        hpke.seal(pk_r, info, aad, ptxt, None, None, None)
    }
    pub fn open(
        &self,
        input: HpkeCiphertext2,
        sk_r: &DHPrivateKey2,
        info: &[u8],
        aad: &[u8],
    ) -> Vec<u8> {
        let hpke = Hpke::new(
            Mode::Base,
            get_kem_from_suite(&self.name),
            get_hpke_kdf_from_suite(&self.name),
            get_hpke_aead_from_suite(&self.name),
        );
        hpke.open(&input.0, sk_r, info, aad, &input.1, None, None, None)
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

    let sealed = csuite.seal(&pk_r, info, aad, ptxt);
    let _ptxt_out = csuite.open(sealed, &sk_r, info, aad);
}

/*

#[derive(Debug, PartialEq)]
pub struct Ciphersuite {
    name: Name,
    hash: digest::Mode,
    kem: hpke::kem::Mode,
    kdf: HmacMode, // Not in spec. Only HKDF is specified here. This can't be used in HPKE, but only standalone
    hpke_aead: hpke::AeadMode, // Not in spec. Should really be the same as aead.
    aead: AeadMode,
    signature: SignatureMode,
}

/// The default ciphersuite is the only mandatory one.
impl Default for Ciphersuite {
    fn default() -> Self {
        Self::new(Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
    }
}

impl Ciphersuite {
    pub fn new(name: Name) -> Self {
        Self {
            name: name,
            hash: get_hash_from_suite(&name),
            kem: get_kem_from_suite(&name),
            kdf: get_kdf_from_suite(&name),
            hpke_aead: get_hpke_aead_from_suite(&name),
            aead: get_aead_from_suite(&name),
            signature: get_signature_from_suite(&name),
        }
    }
    pub fn get_name(&self) -> &Name {
        &self.name
    }
}

impl From<&Name> for u16 {
    fn from(s: &Name) -> u16 {
        *s as u16
    }
}

impl From<u16> for Ciphersuite {
    fn from(v: u16) -> Self {
        let name = match v {
            0x0001 => Name::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            0x0002 => Name::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
            0x0003 => Name::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            0x0004 => Name::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            0x0005 => Name::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521,
            0x0006 => Name::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            _ => panic!("Not implemented."),
        };
        Self::new(name)
    }
}

impl From<Name> for Ciphersuite {
    fn from(v: Name) -> Self {
        Self::new(v)
    }
}
*/
