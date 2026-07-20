//! # Public group diffs
//!
//! This module contains the [`PublicGroupDiff`] struct, as well as the
//! [`StagedPublicGroupDiff`] and associated functions and types.

use serde::{Deserialize, Serialize};

use crate::{
    group::GroupContext,
    messages::ConfirmationTag,
    treesync::diff::StagedTreeSyncDiff,
};

/// The staged version of a [`PublicGroupDiff`], which means it can no longer be
/// modified. Its only use is to merge it into the original [`PublicGroup`].
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StagedPublicGroupDiff {
    pub(super) staged_diff: StagedTreeSyncDiff,
    pub(super) group_context: GroupContext,
    pub(super) interim_transcript_hash: Vec<u8>,
    pub(super) confirmation_tag: ConfirmationTag,
}
