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
use rand::rngs::OsRng;
use rand::RngCore;

pub fn randombytes(n: usize) -> Vec<u8> {
    get_random_vec(n)
}

pub fn random_usize() -> usize {
    OsRng.next_u64() as usize
}

pub fn random_u32() -> u32 {
    OsRng.next_u32()
}

pub fn zero(length: usize) -> Vec<u8> {
    let mut result: Vec<u8> = vec![];
    for _ in 0..length {
        result.push(0u8);
    }
    result
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for b in bytes {
        hex += &format!("{:02X}", *b);
    }
    hex
}

pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        let b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        bytes.push(b);
    }
    bytes
}
