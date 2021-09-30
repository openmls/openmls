//! # Randomness Source for OpenMLS
//!
//! The [`OpenMlsRand`] trait defines the functionality required by OpenMLS to
//! source randomness.

use rand::{CryptoRng, RngCore};

pub trait OpenMlsRand: RngCore + CryptoRng {}
