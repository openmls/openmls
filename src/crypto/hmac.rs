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

use crate::extensions::*;
use hmac::*;
use sha2::{Sha256, Sha512};

#[derive(Copy, Clone)]
pub enum HMACAlgorithm {
    SHA256,
    SHA512,
    INVALID,
}

impl From<CipherSuite> for HMACAlgorithm {
    fn from(value: Ciphersuite) -> Self {
        match value {
            Ciphersuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => HMACAlgorithm::SHA256,
            Ciphersuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => HMACAlgorithm::SHA256,
            Ciphersuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HMACAlgorithm::SHA256
            }
            Ciphersuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => HMACAlgorithm::SHA512,
            Ciphersuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => HMACAlgorithm::SHA512,
            Ciphersuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => HMACAlgorithm::SHA512,
            Ciphersuite::Default => HMACAlgorithm::INVALID,
        }
    }
}

#[derive(Debug)]
pub enum HMACError {
    InvalidKeyLength,
    InvalidAlgorithm,
}

pub fn hash_length(algorithm: HMACAlgorithm) -> usize {
    match algorithm {
        HMACAlgorithm::SHA256 => 32,
        HMACAlgorithm::SHA512 => 64,
        _ => 0,
    }
}

#[allow(clippy::large_enum_variant)]
enum HMACType {
    SHA256(Hmac<Sha256>),
    SHA512(Hmac<Sha512>),
}

pub struct HMAC {
    inner: HMACType,
}

impl HMAC {
    pub fn new(algorithm: HMACAlgorithm, key: &[u8]) -> Result<Self, HMACError> {
        match algorithm {
            HMACAlgorithm::SHA256 => match Hmac::new_varkey(key) {
                Ok(inner) => Ok(Self {
                    inner: HMACType::SHA256(inner),
                }),
                Err(_) => Err(HMACError::InvalidKeyLength),
            },
            HMACAlgorithm::SHA512 => match Hmac::new_varkey(key) {
                Ok(inner) => Ok(Self {
                    inner: HMACType::SHA512(inner),
                }),
                Err(_) => Err(HMACError::InvalidKeyLength),
            },
            HMACAlgorithm::INVALID => Err(HMACError::InvalidAlgorithm),
        }
    }
    pub fn input(&mut self, payload: &[u8]) {
        match &mut self.inner {
            HMACType::SHA256(hmac) => hmac.input(payload),
            HMACType::SHA512(hmac) => hmac.input(payload),
        }
    }
    pub fn result(self) -> Vec<u8> {
        match self.inner {
            HMACType::SHA256(hmac) => hmac.result().code().to_vec(),
            HMACType::SHA512(hmac) => hmac.result().code().to_vec(),
        }
    }
    pub fn verify(self, code: &[u8]) -> bool {
        match self.inner {
            HMACType::SHA256(hmac) => hmac.verify(code).is_ok(),
            HMACType::SHA512(hmac) => hmac.verify(code).is_ok(),
        }
    }
}
