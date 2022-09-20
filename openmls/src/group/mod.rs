//! Group API for MLS
//!
//! This module contains the API to interact with groups.

mod group_context;

use crate::ciphersuite::*;
use crate::extensions::*;
use crate::utils::*;

use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};
use tls_codec::*;

// Crate
pub(crate) mod core_group;
pub(crate) use core_group::*;
pub(crate) mod mls_group;
#[cfg(not(any(feature = "test-utils", test)))]
pub(crate) use group_context::*;

// Public
pub mod errors;

pub use core_group::proposals::*;
pub use core_group::staged_commit::StagedCommit;
pub use mls_group::config::*;
pub use mls_group::membership::*;
pub use mls_group::processing::*;
pub use mls_group::*;

// Tests
#[cfg(any(feature = "test-utils", test))]
pub(crate) use create_commit_params::*;
#[cfg(any(feature = "test-utils", test))]
pub(crate) mod tests;
#[cfg(any(feature = "test-utils", test))]
pub use group_context::GroupContext;
#[cfg(any(feature = "test-utils", test))]
use openmls_traits::random::OpenMlsRand;
#[cfg(any(feature = "test-utils", test))]
pub use proposals::*;

/// A group ID. The group ID is chosen by the creator of the group and should be globally unique.
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

    /// Creates a group ID from a byte slice.
    pub fn from_slice(bytes: &[u8]) -> Self {
        GroupId {
            value: bytes.into(),
        }
    }

    /// Returns the group ID as a byte slice.
    pub fn as_slice(&self) -> &[u8] {
        self.value.as_slice()
    }

    /// Returns the group ID as a byte vector.
    pub fn to_vec(&self) -> Vec<u8> {
        self.value.clone().into()
    }
}

/// Group epoch. Internally this is stored as a `u64`.
/// The group epoch is incremented with every valid Commit that is merged into the group state.
#[derive(
    Debug,
    PartialEq,
    Eq,
    Copy,
    Clone,
    Hash,
    Serialize,
    Deserialize,
    TlsDeserialize,
    TlsSerialize,
    TlsSize,
)]
pub struct GroupEpoch(u64);

impl GroupEpoch {
    /// Increment the group epoch by 1.
    pub(crate) fn increment(&mut self) {
        self.0 += 1;
    }

    /// Returns the group epoch as a `u64`.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl PartialOrd for GroupEpoch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl From<u64> for GroupEpoch {
    fn from(val: u64) -> Self {
        Self(val)
    }
}
