use openmls_traits::types::{HpkeAeadType, HpkeKdfType, HpkeKemType};

use super::*;

pub(crate) use std::convert::TryFrom;

impl From<&CiphersuiteName> for u16 {
    fn from(s: &CiphersuiteName) -> u16 {
        *s as u16
    }
}

impl TryFrom<u16> for CiphersuiteName {
    type Error = tls_codec::Error;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            _ => Err(Self::Error::DecodingError(format!(
                "{} is not a valid cipher suite value",
                v
            ))),
        }
    }
}

#[inline(always)]
pub(crate) fn kem_from_suite(
    ciphersuite_name: &CiphersuiteName,
) -> Result<HpkeKemType, ConfigError> {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
            Ok(HpkeKemType::DhKem25519)
        }
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(HpkeKemType::DhKemP256),
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(HpkeKemType::DhKem25519)
        }
        _ => Err(ConfigError::UnsupportedCiphersuite),
    }
}

#[inline(always)]
pub(crate) fn hpke_kdf_from_suite(ciphersuite_name: &CiphersuiteName) -> HpkeKdfType {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
        | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            HpkeKdfType::HkdfSha256
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
        | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            HpkeKdfType::HkdfSha512
        }
    }
}

#[inline(always)]
pub(crate) fn hpke_aead_from_suite(ciphersuite_name: &CiphersuiteName) -> HpkeAeadType {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => HpkeAeadType::AesGcm128,
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeAeadType::AesGcm128,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            HpkeAeadType::ChaCha20Poly1305
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => HpkeAeadType::AesGcm256,
        CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeAeadType::AesGcm256,
        CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            HpkeAeadType::ChaCha20Poly1305
        }
    }
}
