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
use sha2::{Digest, Sha256, Sha512};

#[derive(Copy, Clone)]
pub enum HashAlgorithm {
    SHA256,
    SHA512,
    INVALID,
}

impl From<CipherSuite> for HashAlgorithm {
    fn from(value: CipherSuite) -> Self {
        match value {
            CipherSuite::MLS10_128_HPKEP256_AES128GCM_SHA256_P256 => HashAlgorithm::SHA256,
            CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519 => HashAlgorithm::SHA256,
            CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
                HashAlgorithm::SHA256
            }
            CipherSuite::MLS10_256_HPKEP521_AES256GCM_SHA512_P521 => HashAlgorithm::SHA512,
            CipherSuite::MLS10_256_HPKEX448_AES256GCM_SHA512_Ed448 => HashAlgorithm::SHA512,
            CipherSuite::MLS10_256_HPKEX448_CHACHA20POLY1305_SHA512_Ed448 => HashAlgorithm::SHA512,
            CipherSuite::Default => HashAlgorithm::INVALID,
        }
    }
}

#[derive(Debug)]
pub enum HashError {
    InputError,
}

pub fn hash_length(algorithm: HashAlgorithm) -> usize {
    match algorithm {
        HashAlgorithm::SHA256 => 32,
        HashAlgorithm::SHA512 => 64,
        _ => 0,
    }
}

pub fn hash(algorithm: HashAlgorithm, payload: &[u8]) -> Vec<u8> {
    match algorithm {
        HashAlgorithm::SHA256 => Sha256::digest(payload).as_slice().to_vec(),
        HashAlgorithm::SHA512 => Sha512::digest(payload).as_slice().to_vec(),
        _ => vec![],
    }
}
