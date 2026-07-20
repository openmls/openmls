//! Group API for MLS
//!
//! This module contains the API to interact with groups.

use std::fmt::Display;

use serde::{Deserialize, Serialize};
use tls_codec::*;

use crate::extensions::*;

// Crate
pub(crate) mod mls_group;
pub(crate) mod public_group;

// Public
pub use group_context::GroupContext;
pub use mls_group::config::*;
pub use mls_group::creation::*;
pub use mls_group::proposal_store::*;
pub use mls_group::staged_commit::StagedCommit;
pub use mls_group::{Member, *};
pub use public_group::*;

// Private
mod group_context;

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
