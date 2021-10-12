//! # OpenMLS Traits
//!
//! This module defines a number of traits that are used by the public
//! API of OpenMLS.

pub mod crypto;
pub mod key_store;
pub mod random;
pub mod types;

pub trait OpenMlsSecurity:
    crypto::OpenMlsCrypto + key_store::OpenMlsKeyStore + random::OpenMlsRand + Send + Sync
{
}
