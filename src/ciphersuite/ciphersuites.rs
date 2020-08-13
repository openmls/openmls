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

use crate::ciphersuite::*;

impl From<&CiphersuiteName> for u16 {
    fn from(s: &CiphersuiteName) -> u16 {
        *s as u16
    }
}

impl From<u16> for CiphersuiteName {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            0x0002 => CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
            0x0003 => CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            0x0004 => CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448,
            0x0005 => CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521,
            0x0006 => CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
            _ => panic!("Not implemented."),
        }
    }
}

pub(crate) fn get_hash_from_suite(ciphersuite_name: &CiphersuiteName) -> DigestMode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => DigestMode::Sha256,
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => DigestMode::Sha256,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            DigestMode::Sha256
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => DigestMode::Sha512,
        CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => DigestMode::Sha512,
        CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => DigestMode::Sha512,
    }
}

pub(crate) fn get_aead_from_suite(ciphersuite_name: &CiphersuiteName) -> AeadMode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => AeadMode::Aes128Gcm,
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => AeadMode::Aes128Gcm,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            AeadMode::Chacha20Poly1305
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => AeadMode::Aes256Gcm,
        CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => AeadMode::Aes256Gcm,
        CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            AeadMode::Chacha20Poly1305
        }
    }
}

pub(crate) fn get_signature_from_suite(ciphersuite_name: &CiphersuiteName) -> SignatureMode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => SignatureMode::Ed25519,
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => SignatureMode::P256,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            SignatureMode::Ed25519
        }
        _ => panic!(
            "Signature scheme for ciphersuite {:?} is not implemented yet.",
            ciphersuite_name
        ),
    }
}

pub(crate) fn get_kem_from_suite(ciphersuite_name: &CiphersuiteName) -> hpke::kem::Mode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
            hpke::kem::Mode::DhKem25519
        }
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => hpke::kem::Mode::DhKemP256,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            hpke::kem::Mode::DhKem25519
        }
        _ => panic!(
            "KEM for ciphersuite {:?} is not implemented yet.",
            ciphersuite_name
        ),
    }
}

pub(crate) fn get_kdf_from_suite(ciphersuite_name: &CiphersuiteName) -> HmacMode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
        | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            HmacMode::Sha256
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
        | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => HmacMode::Sha512,
    }
}

pub(crate) fn get_hpke_kdf_from_suite(ciphersuite_name: &CiphersuiteName) -> HpkeKdfMode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
        | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            hpke::kdf::Mode::HkdfSha256
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
        | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            hpke::kdf::Mode::HkdfSha512
        }
    }
}

pub(crate) fn get_hpke_aead_from_suite(ciphersuite_name: &CiphersuiteName) -> HpkeAeadMode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
            hpke::aead::Mode::AesGcm128
        }
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => hpke::aead::Mode::AesGcm128,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            hpke::aead::Mode::ChaCha20Poly1305
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => hpke::aead::Mode::AesGcm256,
        CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => hpke::aead::Mode::AesGcm256,
        CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            hpke::aead::Mode::ChaCha20Poly1305
        }
    }
}
