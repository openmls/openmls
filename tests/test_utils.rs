#![allow(dead_code)]

use evercrypt::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;

pub(crate) fn random_usize() -> usize {
    OsRng.next_u64() as usize
}

pub(crate) fn randombytes(n: usize) -> Vec<u8> {
    get_random_vec(n)
}

pub(crate) fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        bytes.push(b);
    }
    bytes
}
