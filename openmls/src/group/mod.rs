//! Group API for MLS
//!
//! This module contains the API to interact with groups.

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use tls_codec::*;

use crate::extensions::*;
use openmls_traits::random::OpenMlsRand;

#[cfg(test)]
use crate::ciphersuite::*;
#[cfg(test)]
use crate::utils::*;

// Crate
pub(crate) mod errors;
pub(crate) mod mls_group;
pub(crate) mod public_group;

// Public
pub use errors::*;
pub use group_context::GroupContext;
pub use mls_group::config::*;
pub use mls_group::membership::*;
pub use mls_group::proposal_store::*;
pub use mls_group::staged_commit::StagedCommit;
pub use mls_group::{Member, *};
pub use public_group::*;

// Private
mod group_context;

// Tests
#[cfg(any(feature = "test-utils", test))]
pub(crate) mod tests_and_kats;

/// A group ID. The group ID is chosen by the creator of the group and should be globally unique.
#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    TlsDeserialize,
    TlsDeserializeBytes,
    TlsSerialize,
    TlsSize,
)]
pub struct GroupId {
    value: VLBytes,
}

impl GroupId {
    /// Create a new (random) group ID.
    ///
    /// Group IDs should be random and not be misused as, e.g., a group name.
    pub fn random(rng: &impl OpenMlsRand) -> Self {
        Self {
            value: rng.random_vec(16).expect("Not enough randomness.").into(),
        }
    }

    /// Create a group ID from a byte slice.
    ///
    /// This should be used only if the group ID is chosen by an entity that ensures uniqueness.
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
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Deserialize,
    Serialize,
    TlsDeserialize,
    TlsDeserializeBytes,
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

impl From<u64> for GroupEpoch {
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl Display for GroupEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}
