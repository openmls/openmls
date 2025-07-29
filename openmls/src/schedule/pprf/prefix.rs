//! This module defines a trait for prefixes to instantiate a PPRF depending on
//! the PPRF's index (i.e. input) size.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub trait Prefix: Clone + Eq + std::hash::Hash + Serialize + DeserializeOwned {
    /// The maximum depth of the prefix in bits. Must be a multiple of 8.
    const MAX_DEPTH: usize;

    const MAX_INPUT_LEN: usize = Self::MAX_DEPTH / 8; // In bytes

    /// Create an empty prefix
    fn new() -> Self;

    /// Push a bit (left or right aligned)
    fn push_bit(&mut self, bit: bool);
}

/// A 256-bit prefix implementation for PPRF.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixVec {
    bits: Vec<u8>,
    len: u16,
}

impl Prefix for PrefixVec {
    const MAX_DEPTH: usize = 256;

    fn new() -> Self {
        Self {
            bits: vec![],
            len: 0,
        }
    }

    fn push_bit(&mut self, bit: bool) {
        if self.len % 8 == 0 {
            self.bits.push(0);
        }
        if bit {
            let byte_index = self.len / 8;
            let bit_index = 7 - (self.len % 8);
            self.bits[byte_index as usize] |= 1 << bit_index;
        }
        self.len += 1;
    }
}

#[derive(Serialize, Deserialize)]
struct SerdePrefixVec(#[serde(with = "serde_bytes")] Vec<u8>, u16);

impl From<PrefixVec> for SerdePrefixVec {
    fn from(prefix: PrefixVec) -> Self {
        SerdePrefixVec(prefix.bits, prefix.len)
    }
}

impl From<SerdePrefixVec> for PrefixVec {
    fn from(prefix: SerdePrefixVec) -> Self {
        PrefixVec {
            bits: prefix.0,
            len: prefix.1,
        }
    }
}

/// A 32-bit prefix implementation for PPRF.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "SerdePrefix32", into = "SerdePrefix32")]
pub struct Prefix32 {
    bits: u32,
    len: u8,
}

impl Prefix32 {
    /// The largest dummy prefix that can be used for testing.
    pub fn large_dummy_prefix() -> Self {
        let mut prefix = Self::new();
        for _ in 0..Self::MAX_DEPTH {
            prefix.push_bit(true);
        }
        prefix
    }
}

impl Prefix for Prefix32 {
    const MAX_DEPTH: usize = 32;

    fn new() -> Self {
        Self { bits: 0, len: 0 }
    }

    fn push_bit(&mut self, bit: bool) {
        self.bits <<= 1;
        if bit {
            self.bits |= 1;
        }
        self.len += 1;
    }
}

#[derive(Serialize, Deserialize)]
struct SerdePrefix32(u32, u8);

impl From<Prefix32> for SerdePrefix32 {
    fn from(prefix: Prefix32) -> Self {
        SerdePrefix32(prefix.bits, prefix.len)
    }
}

impl From<SerdePrefix32> for Prefix32 {
    fn from(prefix: SerdePrefix32) -> Self {
        Prefix32 {
            bits: prefix.0,
            len: prefix.1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "SerdePrefix16", into = "SerdePrefix16")]
pub struct Prefix16 {
    bits: u16,
    len: u8,
}

impl Prefix16 {
    /// The largest dummy prefix that can be used for testing.
    pub fn large_dummy_prefix() -> Self {
        let mut prefix = Self::new();
        for _ in 0..Self::MAX_DEPTH {
            prefix.push_bit(true);
        }
        prefix
    }
}

impl Prefix for Prefix16 {
    const MAX_DEPTH: usize = 16;

    fn new() -> Self {
        Self { bits: 0, len: 0 }
    }

    fn push_bit(&mut self, bit: bool) {
        self.bits <<= 1;
        if bit {
            self.bits |= 1;
        }
        self.len += 1;
    }
}

#[derive(Serialize, Deserialize)]
struct SerdePrefix16(u16, u8);

impl From<Prefix16> for SerdePrefix16 {
    fn from(prefix: Prefix16) -> Self {
        SerdePrefix16(prefix.bits, prefix.len)
    }
}

impl From<SerdePrefix16> for Prefix16 {
    fn from(prefix: SerdePrefix16) -> Self {
        Prefix16 {
            bits: prefix.0,
            len: prefix.1,
        }
    }
}
