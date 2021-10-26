//! # Randomness Source for OpenMLS
//!
//! The [`OpenMlsRand`] trait defines the functionality required by OpenMLS to
//! source randomness.

use std::fmt::Debug;

pub trait OpenMlsRand {
    type Error: Debug + Clone + PartialEq + Into<String>;

    /// Fill an array with random bytes.
    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error>;

    /// Fill a vector of length `len` with bytes.
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error>;
}
