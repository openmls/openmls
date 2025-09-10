//! This module defines a trait for prefixes to instantiate a PPRF depending on
//! the PPRF's index (i.e. input) size. It also provides implementations for
//! different tree sizes.
//!
//! Each prefix encodes a node in the binary tree of the PPRF. The root node has
//! an empty prefix, which then grows in size with each step down the tree.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

pub trait Prefix: Clone + Eq + std::hash::Hash + Serialize + DeserializeOwned {
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
