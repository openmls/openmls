//! # Randomness Source for OpenMLS
//!
//! The [`OpenMlsRand`] trait defines the functionality required by OpenMLS to
//! source randomness.

pub trait OpenMlsRand {
    /// Fill an array with random bytes.
    fn random_array<const N: usize>(&self) -> [u8; N];

    /// Fill a vector of length `len` with bytes.
    fn random_vec(&self, len: usize) -> Vec<u8>;
}
