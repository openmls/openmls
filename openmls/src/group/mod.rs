//! Group APIs for MLS
//!
//! This file contains the API to interact with groups.
//!
//! The low-level standard API is described in the `Api` trait.\
//! The high-level API is exposed in `MlsGroup`.

mod group_context;
mod mls_group;

use crate::ciphersuite::*;
use crate::extensions::*;
use crate::utils::*;

use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};
use tls_codec::*;

// Crate
pub(crate) mod core_group;
pub(crate) mod errors;
pub(crate) use core_group::*;
pub(crate) use errors::{
    CoreGroupError, CreateCommitError, ExporterError, InterimTranscriptHashError, StageCommitError,
    WelcomeError,
};
pub(crate) use group_context::*;

// Public
pub use mls_group::*;

// Tests
#[cfg(any(feature = "test-utils", test))]
pub(crate) mod tests;
#[cfg(any(feature = "test-utils", test))]
pub use create_commit_params::*;
#[cfg(any(feature = "test-utils", test))]
use openmls_traits::random::OpenMlsRand;
#[cfg(any(feature = "test-utils", test))]
pub use proposals::*;

#[derive(
    Hash, Eq, Debug, PartialEq, Clone, Serialize, Deserialize, TlsSerialize, TlsDeserialize, TlsSize,
)]
pub struct GroupId {
    value: TlsByteVecU8,
}

impl GroupId {
    #[cfg(any(feature = "test-utils", test))]
    pub fn random(rng: &impl OpenMlsCryptoProvider) -> Self {
        Self {
            value: rng
                .rand()
                .random_vec(16)
                .expect("Not enough randomness.")
                .into(),
        }
    }
    pub fn from_slice(bytes: &[u8]) -> Self {
        GroupId {
            value: bytes.into(),
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }
    pub fn to_vec(&self) -> Vec<u8> {
        self.value.clone().into()
    }
}

#[derive(
    Debug,
    PartialEq,
    Copy,
    Clone,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct GroupEpoch(pub u64);

impl GroupEpoch {
    pub fn increment(&mut self) {
        self.0 += 1;
    }
}

impl PartialOrd for GroupEpoch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}
