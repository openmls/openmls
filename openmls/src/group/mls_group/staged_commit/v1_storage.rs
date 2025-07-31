//! This module contains legacy structs and implementations for storage provider
//! version 1.

use serde::{Deserialize, Serialize};

use super::StagedCommitState;

use crate::{
    group::{
        diff::StagedPublicGroupDiff, mls_group::staged_commit::MemberStagedCommitState,
        public_group::staged_commit::PublicStagedCommitState, MlsGroupState, PendingCommitState,
        ProposalQueue, StagedCommit,
    },
    schedule::{message_secrets::MessageSecrets, GroupEpochSecrets},
    treesync::node::{encryption_keys::EncryptionKeyPair, leaf_node::LeafNode},
};

/// This struct is used internally by [StagedCommit] to encapsulate all the modified group state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub(crate) struct MemberStagedCommitStateV1 {
    group_epoch_secrets: GroupEpochSecrets,
    message_secrets: MessageSecrets,
    staged_diff: StagedPublicGroupDiff,
    new_keypairs: Vec<EncryptionKeyPair>,
    new_leaf_keypair_option: Option<EncryptionKeyPair>,
    update_path_leaf_node: Option<LeafNode>,
}

impl From<MemberStagedCommitStateV1> for MemberStagedCommitState {
    fn from(state: MemberStagedCommitStateV1) -> Self {
        let MemberStagedCommitStateV1 {
            group_epoch_secrets,
            message_secrets,
            staged_diff,
            new_keypairs,
            new_leaf_keypair_option,
            update_path_leaf_node,
        } = state;

        MemberStagedCommitState {
            group_epoch_secrets,
            message_secrets,
            staged_diff,
            new_keypairs,
            new_leaf_keypair_option,
            update_path_leaf_node,
            #[cfg(feature = "extensions-draft-08")]
            application_exporter: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub(crate) enum StagedCommitStateV1 {
    PublicState(Box<PublicStagedCommitState>),
    GroupMember(Box<MemberStagedCommitStateV1>),
}

impl From<StagedCommitStateV1> for StagedCommitState {
    fn from(state: StagedCommitStateV1) -> Self {
        match state {
            StagedCommitStateV1::PublicState(public_state) => {
                StagedCommitState::PublicState(public_state)
            }
            StagedCommitStateV1::GroupMember(member_state) => StagedCommitState::GroupMember(
                Box::new(MemberStagedCommitState::from(*member_state)),
            ),
        }
    }
}

/// Contains the changes from a commit to the group state.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub struct StagedCommitV1 {
    staged_proposal_queue: ProposalQueue,
    state: StagedCommitStateV1,
}

impl From<StagedCommitV1> for StagedCommit {
    fn from(staged_commit: StagedCommitV1) -> Self {
        Self {
            staged_proposal_queue: staged_commit.staged_proposal_queue,
            state: match staged_commit.state {
                StagedCommitStateV1::PublicState(public_state) => {
                    StagedCommitState::PublicState(public_state)
                }
                StagedCommitStateV1::GroupMember(member_state) => StagedCommitState::GroupMember(
                    Box::new(MemberStagedCommitState::from(*member_state)),
                ),
            },
        }
    }
}

/// Pending Commit state. Differentiates between Commits issued by group members
/// and External Commits.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub enum PendingCommitStateV1 {
    /// Commit from a group member
    Member(StagedCommitV1),
    /// Commit from an external joiner
    External(StagedCommitV1),
}

impl From<PendingCommitStateV1> for PendingCommitState {
    fn from(state: PendingCommitStateV1) -> Self {
        match state {
            PendingCommitStateV1::Member(staged_commit) => {
                PendingCommitState::Member(staged_commit.into())
            }
            PendingCommitStateV1::External(staged_commit) => {
                PendingCommitState::External(staged_commit.into())
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(any(test, feature = "test-utils"), derive(Clone, PartialEq))]
pub enum MlsGroupStateV1 {
    /// There is currently a pending Commit that hasn't been merged yet.
    PendingCommit(Box<PendingCommitStateV1>),
    /// The group state is in an opertaional state, where new messages and Commits can be created.
    Operational,
    /// The group is inactive because the member has been removed.
    Inactive,
}

impl From<MlsGroupStateV1> for MlsGroupState {
    fn from(state: MlsGroupStateV1) -> Self {
        match state {
            MlsGroupStateV1::PendingCommit(pending_commit) => {
                MlsGroupState::PendingCommit(Box::new(PendingCommitState::from(*pending_commit)))
            }
            MlsGroupStateV1::Operational => MlsGroupState::Operational,
            MlsGroupStateV1::Inactive => MlsGroupState::Inactive,
        }
    }
}
