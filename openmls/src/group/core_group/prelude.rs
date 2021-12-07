//! Prelude for the CoreGroup feature.
//! Include this to get access to public functions used in conjunction with the [`CoreGroup`].

// CoreGroup
pub use crate::group::{
    create_commit_params::{CreateCommitParams, CreateCommitParamsBuilder},
    proposals::{ProposalStore, StagedProposal},
    CoreGroup, CoreGroupConfig, InvalidMessageError, ManagedGroupConfig, ManagedGroupError,
    UpdatePolicy,
};

// Indexes
pub use crate::tree::index::LeafIndex;

// Framing
pub use crate::framing::{errors::*, sender::Sender, *};

// Config
pub use crate::config::*;

// Utils
pub use crate::utils::*;
