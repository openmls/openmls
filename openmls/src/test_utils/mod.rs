//! Test utilities
#![allow(dead_code)]
#![allow(unused_imports)]

pub use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
pub use rstest::*;
pub use rstest_reuse::{self, *};

pub use crate::utils::*;

use serde::{self, de::DeserializeOwned, Serialize};
use std::fmt::Write as FmtWrite;
use std::{
    fs::File,
    io::{BufReader, Write},
};

pub mod test_framework;

pub(crate) fn write(file_name: &str, obj: impl Serialize) {
    let mut file = match File::create(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {}.", file_name),
    };
    file.write_all(
        serde_json::to_string_pretty(&obj)
            .expect("Error serializing test vectors")
            .as_bytes(),
    )
    .expect("Error writing test vector file");
}

pub(crate) fn read<T: DeserializeOwned>(file_name: &str) -> T {
    let file = match File::open(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {}.", file_name),
    };
    let reader = BufReader::new(file);
    match serde_json::from_reader(reader) {
        Ok(r) => r,
        Err(e) => panic!("Error reading file.\n{:?}", e),
    }
}

/// Convert `bytes` to a hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for &b in bytes {
        write!(&mut hex, "{:02X}", b).expect("Unable to write to string");
    }
    hex
}

/// Convert a hex string to a byte vector.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0);
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        bytes.push(
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("An unexpected error occurred."),
        );
    }
    bytes
}

/// Convert a hex string to a byte vector.
/// If the input is `None`, this returns an empty vector.
pub fn hex_to_bytes_option(hex: Option<String>) -> Vec<u8> {
    match hex {
        Some(s) => hex_to_bytes(&s),
        None => vec![],
    }
}

// === Define backend per platform ===

// For now we only use Evercrypt on specific platforms and only if the feature was enabled

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm"),
    feature = "evercrypt",
))]
pub use openmls_evercrypt::OpenMlsEvercrypt;

// This backend is currently used on all platforms
pub use openmls_rust_crypto::OpenMlsRustCrypto;

// === Backends ===

#[cfg(any(
    not(target_arch = "x86_64"),
    target_os = "macos",
    target_family = "wasm",
    not(feature = "evercrypt")
))]
#[template]
#[export]
#[rstest(backend,
    case::rust_crypto(&OpenMlsRustCrypto::default()),
  )
]
#[allow(non_snake_case)]
pub fn backends(backend: &impl OpenMlsCryptoProvider) {}

// For now we only use Evercrypt on specific platforms and only if the feature was enabled

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm"),
    feature = "evercrypt",
))]
#[template]
#[export]
#[rstest(backend,
    case::rust_crypto(&OpenMlsRustCrypto::default()),
    case::evercrypt(&openmls_evercrypt::OpenMlsEvercrypt::default()),
  )
]
#[allow(non_snake_case)]
pub fn backends(backend: &impl OpenMlsCryptoProvider) {}

// === Ciphersuites ===

// For now we support all ciphersuites, regardless of the backend

#[template]
#[export]
#[rstest(
    ciphersuite,
    case::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    ),
    case::MLS_128_DHKEMP256_AES128GCM_SHA256_P256(
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    ),
    case::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )
)]
#[allow(non_snake_case)]
pub fn ciphersuites(ciphersuite: Ciphersuite) {}

// === Ciphersuites & backends ===

#[cfg(any(
    not(target_arch = "x86_64"),
    target_os = "macos",
    target_family = "wasm",
    not(feature = "evercrypt"),
))]
#[template]
#[export]
#[rstest(ciphersuite, backend,
    case::rust_crypto_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
  )
]
#[allow(non_snake_case)]
pub fn ciphersuites_and_backends(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {}

// For now we only use Evercrypt on specific platforms and only if the feature was enabled

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm"),
    feature = "evercrypt",
))]
#[template]
#[export]
#[rstest(ciphersuite, backend,
    case::rust_crypto_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::evercrypt_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &openmls_evercrypt::OpenMlsEvercrypt::default()),
    case::evercrypt_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &openmls_evercrypt::OpenMlsEvercrypt::default()),
    case::evercrypt_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &openmls_evercrypt::OpenMlsEvercrypt::default()),
  )
]
#[allow(non_snake_case)]
pub fn ciphersuites_and_backends(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {}
