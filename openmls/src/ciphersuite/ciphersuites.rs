use super::*;
use crate::codec::CodecError;

pub(crate) use std::convert::TryFrom;

impl From<&CiphersuiteName> for u16 {
    fn from(s: &CiphersuiteName) -> u16 {
        *s as u16
    }
}

impl TryFrom<u16> for CiphersuiteName {
    type Error = CodecError;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            _ => Err(CodecError::DecodingError),
        }
    }
}

pub(crate) fn hash_from_suite(ciphersuite_name: &CiphersuiteName) -> DigestMode {
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

pub(crate) fn aead_from_suite(ciphersuite_name: &CiphersuiteName) -> AeadMode {
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

pub(crate) fn kem_from_suite(
    ciphersuite_name: &CiphersuiteName,
) -> Result<HpkeKemMode, ConfigError> {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
            Ok(HpkeKemMode::DhKem25519)
        }
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => Ok(HpkeKemMode::DhKemP256),
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            Ok(HpkeKemMode::DhKem25519)
        }
        _ => Err(ConfigError::UnsupportedCiphersuite),
    }
}

pub(crate) fn kdf_from_suite(ciphersuite_name: &CiphersuiteName) -> HmacMode {
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

pub(crate) fn hpke_kdf_from_suite(ciphersuite_name: &CiphersuiteName) -> HpkeKdfMode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        | CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
        | CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            HpkeKdfMode::HkdfSha256
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448
        | CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521
        | CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            HpkeKdfMode::HkdfSha512
        }
    }
}

pub(crate) fn hpke_aead_from_suite(ciphersuite_name: &CiphersuiteName) -> HpkeAeadMode {
    match ciphersuite_name {
        CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => HpkeAeadMode::AesGcm128,
        CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 => HpkeAeadMode::AesGcm128,
        CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 => {
            HpkeAeadMode::ChaCha20Poly1305
        }
        CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 => HpkeAeadMode::AesGcm256,
        CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 => HpkeAeadMode::AesGcm256,
        CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 => {
            HpkeAeadMode::ChaCha20Poly1305
        }
    }
}
