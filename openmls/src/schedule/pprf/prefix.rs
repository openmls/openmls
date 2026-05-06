//! This module defines a trait for prefixes to instantiate a PPRF depending on
//! the PPRF's index (i.e. input) size. It also provides an implementation for
//! trees with u16 as the leaf index type.
//!
//! Each prefix encodes a node in the binary tree of the PPRF. The root node has
//! an empty prefix, which then grows in size with each step down the tree.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_bytes::ByteArray;

pub(crate) trait Prefix:
    Clone + Eq + std::hash::Hash + Serialize + DeserializeOwned
{
    /// The maximum depth of the prefix in bits. Must be a multiple of 8.
    const MAX_DEPTH: usize;

    /// The maximum input length based on the maximum depth supported by the
    /// prefix.
    const MAX_INPUT_LEN: usize = Self::MAX_DEPTH / 8; // In bytes

    /// Create an empty prefix
    fn new() -> Self;

    /// Push a bit (left or right aligned)
    fn push_bit(&mut self, bit: bool);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "SerdePrefix16", into = "SerdePrefix16")]
pub struct Prefix16 {
    /// A u16 containing the bits of the prefix.
    bits: u16,
    /// The number of bits in the prefix.
    len: u8,
}

impl Prefix for Prefix16 {
    const MAX_DEPTH: usize = 16;

    fn new() -> Self {
        Self { bits: 0, len: 0 }
    }

    fn push_bit(&mut self, bit: bool) {
        self.bits = self.bits << 1 | u16::from(bit);
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

/// A prefix in a PPRF whose inputs are 32-byte (256-bit) strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "SerdePrefix256", into = "SerdePrefix256")]
pub struct Prefix256 {
    bits: [u8; 32],
    len: u16,
}

impl Prefix for Prefix256 {
    const MAX_DEPTH: usize = 256;

    fn new() -> Self {
        Self {
            bits: [0; 32],
            len: 0,
        }
    }

    fn push_bit(&mut self, bit: bool) {
        if bit {
            let byte_idx = (self.len / 8) as usize;
            let bit_idx = 7 - (self.len % 8) as u8;
            self.bits[byte_idx] |= 1 << bit_idx;
        }
        self.len += 1;
    }
}

#[derive(Serialize, Deserialize)]
struct SerdePrefix256(ByteArray<32>, u16);

impl From<Prefix256> for SerdePrefix256 {
    fn from(prefix: Prefix256) -> Self {
        SerdePrefix256(ByteArray::new(prefix.bits), prefix.len)
    }
}

impl From<SerdePrefix256> for Prefix256 {
    fn from(prefix: SerdePrefix256) -> Self {
        Prefix256 {
            bits: prefix.0.into_array(),
            len: prefix.1,
        }
    }
}
