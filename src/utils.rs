#![allow(dead_code)]
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

use rand::rngs::OsRng;
use rand::RngCore;

pub fn randombytes(n: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(n);
    for _ in 0..n {
        bytes.push(0);
    }
    OsRng.fill_bytes(&mut bytes);
    bytes
}

pub fn random_usize() -> usize {
    OsRng.next_u64() as usize
}

pub fn random_u32() -> u32 {
    OsRng.next_u32()
}

pub(crate) fn u32_to_bytes(d: &[u32]) -> Vec<u8> {
    let mut out = Vec::<u8>::new();
    for e in d.iter() {
        out.push((e & 0xFF) as u8);
        out.push(((e & 0xFF00) >> 8) as u8);
        out.push(((e & 0xFF0000) >> 16) as u8);
        out.push(((e & 0xFF000000) >> 24) as u8);
    }
    out
}

pub(crate) fn bytes_to_u32(bytes: &[u8]) -> Vec<u32> {
    debug_assert!(bytes.len() % 4 == 0);
    let mut out = Vec::<u32>::new();
    for i in (0..bytes.len()).step_by(4) {
        out.push((bytes[i+3] as u32) << 24 | (bytes[i+2] as u32) << 16 |
                 (bytes[i+1] as u32) << 8  | bytes[i] as u32);
    }
    debug_assert!(out.len() == bytes.len() / 4);
    out
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
