//! # Randomness Source for OpenMLS
//!
//! The [`OpenMlsRand`] trait defines the functionality required by OpenMLS to
//! source randomness.

use std::fmt::Debug;

// ANCHOR: openmls_rand
pub trait OpenMlsRand {
    type Error: std::error::Error + Debug;

    /// Fill an array with random bytes.
    fn random_array<const N: usize>(&self) -> Result<[u8; N], Self::Error>;

    /// Fill a vector of length `len` with bytes.
    fn random_vec(&self, len: usize) -> Result<Vec<u8>, Self::Error>;

    /// Sample randomness for the reuse guard.
    fn reuse_guard<const N: usize>(&self) -> Result<[u8; N], Self::Error> {
        self.random_array::<N>()
    }

    /// Sample randomness for an `InitSecret`.
    fn init_secret(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.random_vec(len)
    }

    /// Sample randomness for generating an init key pair.
    fn init_key_seed(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.random_vec(len)
    }

    /// Sample randomness for generating a path secret.
    fn path_secret(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.random_vec(len)
    }

    /// Sample randomness for generating a path secret.
    fn encryption_key_seed(&self, len: usize) -> Result<Vec<u8>, Self::Error> {
        self.random_vec(len)
    }
}
// ANCHOR_END: openmls_rand
