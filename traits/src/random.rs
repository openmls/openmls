//! # Randomness Source for OpenMLS
//!
//! The [`OpenMlsRand`] trait defines the functionality required by OpenMLS to
//! source randomness.

pub trait OpenMlsRand {
    fn random_array<const N: usize>(&self) -> [u8; N];
    fn random_vec(&self, len: usize) -> Vec<u8>;
}
