use std::convert::TryFrom;

use test_macros::ctest;

#[allow(non_camel_case_types)]
#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, Clone)]
#[repr(u16)]
pub enum CiphersuiteName {
    MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    MLS10_128_DHKEMP256_AES128GCM_SHA256_P256 = 0x0002,
    MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519 = 0x0003,
    MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448 = 0x0004,
    MLS10_256_DHKEMP521_AES256GCM_SHA512_P521 = 0x0005,
    MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448 = 0x0006,
}

impl TryFrom<u16> for CiphersuiteName {
    type Error = &'static str;

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0001 => Ok(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
            0x0002 => Ok(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256),
            0x0003 => Ok(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519),
            0x0004 => Ok(CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448),
            0x0005 => Ok(CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521),
            0x0006 => Ok(CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448),
            _ => Err("Unknown ciphersuite"),
        }
    }
}

ctest!(ciphersuite_test [
    CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
    CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
] {
    println!("Testing ciphersuite {:?}", param);
});

macro_rules! ctest_ciphersuites {
    ($name:ident, test($param_name:ident: $t:ty) $body:block) => {
        ctest!(
            $name
            [
                CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
                CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ]
            {
                fn test($param_name: $t) $body
                test(param)
            }
        );
    };
}

ctest_ciphersuites!(better_test, test(ciphersuite_name: CiphersuiteName) {
    println!("Testing ciphersuite {:?}", ciphersuite_name);
});
