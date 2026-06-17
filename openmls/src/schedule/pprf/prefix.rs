//! This module defines a trait for prefixes to instantiate a PPRF depending on
//! the PPRF's index (i.e. input) size. It also provides an implementation for
//! trees with u16 as the leaf index type.
//!
//! Each prefix encodes a node in the binary tree of the PPRF. The root node has
//! an empty prefix, which then grows in size with each step down the tree.

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::PprfError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
#[serde(bound(
    serialize = "T: Serialize",
    deserialize = "T: Copy + Into<usize> + Deserialize<'de>"
))]
struct PrefixLen<const MAX_DEPTH: usize, T>
where
    T: Copy + Into<usize>,
{
    #[serde(deserialize_with = "deserialize_prefix_len::<MAX_DEPTH, T, _>")]
    len: T,
}

impl<const MAX_DEPTH: usize, T> PrefixLen<MAX_DEPTH, T>
where
    T: Copy + Into<usize>,
{
    fn new(len: T) -> Result<Self, PprfError> {
        if len.into() > MAX_DEPTH {
            return Err(PprfError::PrefixMaxDepthExceeded);
        }
        Ok(Self { len })
    }

    fn as_usize(self) -> usize {
        self.len.into()
    }
}

impl<const MAX_DEPTH: usize, T> PrefixLen<MAX_DEPTH, T>
where
    T: Copy + From<u8> + Into<usize>,
{
    fn zero() -> Self {
        Self { len: T::from(0) }
    }
}

impl<const MAX_DEPTH: usize, T> PrefixLen<MAX_DEPTH, T>
where
    T: Copy + Into<usize> + TryFrom<usize>,
{
    fn incremented(self) -> Result<Self, PprfError> {
        let Some(len) = self.as_usize().checked_add(1) else {
            return Err(PprfError::PrefixMaxDepthExceeded);
        };
        let Ok(len) = T::try_from(len) else {
            return Err(PprfError::PrefixMaxDepthExceeded);
        };
        Self::new(len)
    }
}

fn deserialize_prefix_len<'de, const MAX_DEPTH: usize, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: Copy + Into<usize> + Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    let len = T::deserialize(deserializer)?;
    PrefixLen::<MAX_DEPTH, T>::new(len)
        .map(|prefix_len| prefix_len.len)
        .map_err(serde::de::Error::custom)
}

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
    fn push_bit(&mut self, bit: bool) -> Result<(), PprfError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "SerdePrefix16", into = "SerdePrefix16")]
pub struct Prefix16 {
    /// A u16 containing the bits of the prefix.
    bits: u16,
    /// The number of bits in the prefix.
    len: PrefixLen<{ Self::MAX_DEPTH }, u8>,
}

impl Prefix for Prefix16 {
    const MAX_DEPTH: usize = 16;

    fn new() -> Self {
        Self {
            bits: 0,
            len: PrefixLen::zero(),
        }
    }

    fn push_bit(&mut self, bit: bool) -> Result<(), PprfError> {
        let len = self.len.incremented()?;
        self.bits = self.bits << 1 | u16::from(bit);
        self.len = len;
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct SerdePrefix16(u16, PrefixLen<{ Prefix16::MAX_DEPTH }, u8>);

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

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix_len<const MAX_DEPTH: usize, T>(len: T) -> PrefixLen<MAX_DEPTH, T>
    where
        T: Copy + Into<usize>,
    {
        match PrefixLen::new(len) {
            Ok(prefix_len) => prefix_len,
            Err(error) => panic!("{error}"),
        }
    }

    #[test]
    fn prefix16_rejects_push_at_max_depth() {
        let max_depth = Prefix16::MAX_DEPTH as u8;
        let mut prefix = Prefix16 {
            bits: u16::MAX,
            len: prefix_len(max_depth),
        };

        let result = prefix.push_bit(true);

        assert_eq!(result, Err(PprfError::PrefixMaxDepthExceeded));
        assert_eq!(prefix.len.len, max_depth);
        assert_eq!(prefix.bits, u16::MAX);
    }

    #[test]
    fn prefix_len_new_rejects_len_greater_than_max_depth() {
        let result = PrefixLen::<{ Prefix16::MAX_DEPTH }, u8>::new(17);

        assert_eq!(result, Err(PprfError::PrefixMaxDepthExceeded));
    }

    #[test]
    fn prefix_len_rejects_len_greater_than_max_depth() {
        let result = serde_json::from_str::<PrefixLen<{ Prefix16::MAX_DEPTH }, u8>>("17");

        assert!(result.is_err());
    }

    #[test]
    fn prefix_len_accepts_len_at_max_depth() {
        let result = serde_json::from_str::<PrefixLen<{ Prefix16::MAX_DEPTH }, u8>>("16").unwrap();

        assert_eq!(result.len, Prefix16::MAX_DEPTH as u8);
    }
}
