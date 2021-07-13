//! Test utilities
#![allow(dead_code)]

use serde::{self, de::DeserializeOwned, Serialize};
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
pub(crate) fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for &b in bytes {
        hex += &format!("{:02X}", b);
    }
    hex
}

/// Convert a hex string to a byte vector.
pub(crate) fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0);
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        bytes.push(u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap());
    }
    bytes
}

/// Convert a hex string to a byte vector.
/// If the input is `None`, this returns an empty vector.
pub(crate) fn hex_to_bytes_option(hex: Option<String>) -> Vec<u8> {
    match hex {
        Some(s) => hex_to_bytes(&s),
        None => vec![],
    }
}

#[allow(unused_macros)]
macro_rules! ctest_ciphersuites {
    ($name:ident, test($param_name:ident: $t:ty) $body:block) => {
        test_macros::ctest!(
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
