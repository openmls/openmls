use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use super::{GroupEpochSecrets, LeafNode, MessageSecrets, ProposalQueue};
#[cfg(feature = "extensions-draft-08")]
use crate::schedule::application_export_tree::ApplicationExportTree;

use crate::{
    group::public_group::{diff::StagedPublicGroupDiff, staged_commit::PublicStagedCommitState},
    treesync::node::encryption_keys::EncryptionKeyPair,
};

#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum StagedCommitState {
    PublicState(Box<PublicStagedCommitState>),
    GroupMember(Box<MemberStagedCommitState>),
}

/// Contains the changes from a commit to the group state.
#[derive(Debug, Serialize, Deserialize)]
pub struct StagedCommit {
    staged_proposal_queue: ProposalQueue,
    state: StagedCommitState,
}

/// This struct is used internally by [StagedCommit] to encapsulate all the modified group state.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MemberStagedCommitState {
    group_epoch_secrets: GroupEpochSecrets,
    message_secrets: MessageSecrets,
    staged_diff: StagedPublicGroupDiff,
    new_keypairs: Vec<EncryptionKeyPair>,
    new_leaf_keypair_option: Option<EncryptionKeyPair>,
    update_path_leaf_node: Option<LeafNode>,
    #[cfg(feature = "extensions-draft-08")]
    #[serde(default)]
    // This is `None` only if the group was stored using an older version of
    // OpenMLS that did not support the application exporter.
    application_export_tree: Option<ApplicationExportTree>,
}
