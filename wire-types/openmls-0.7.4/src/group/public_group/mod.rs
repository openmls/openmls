//! # Public Groups
//!
//! There are a few use-cases that require the tracking of an MLS group based on
//! [`PublicMessage`]s, e.g. for group membership tracking by a delivery
//! service.
//!
//! This module and its submodules contain the [`PublicGroup`] struct, as well
//! as associated helper structs the goal of which is to enable this
//! functionality.
//!
//! To avoid duplication of code and functionality, [`MlsGroup`] internally
//! relies on a [`PublicGroup`] as well.

#[cfg(feature = "migration-export")]
use openmls_traits::types::Ciphersuite;

use serde::{Deserialize, Serialize};

use self::diff::StagedPublicGroupDiff;
use super::{proposal_store::ProposalStore, GroupContext};
#[cfg(feature = "migration-export")]
use super::{proposal_store::QueuedProposal, GroupId};
#[cfg(feature = "migration-export")]
use crate::{ciphersuite::hash_ref::ProposalRef, storage::PublicStorageProvider};
#[cfg(doc)]
use crate::{framing::PublicMessage, group::MlsGroup};
use crate::{
    messages::ConfirmationTag,
    treesync::{node::leaf_node::LeafNode, TreeSync},
};

pub(crate) mod diff;
pub(crate) mod staged_commit;

/// This struct holds all public values of an MLS group.
#[derive(Debug)]
#[cfg_attr(feature = "migration-export", derive(serde::Serialize))]
pub struct PublicGroup {
    treesync: TreeSync,
    proposal_store: ProposalStore,
    group_context: GroupContext,
    interim_transcript_hash: Vec<u8>,
    // Most recent confirmation tag. Kept here for verification purposes.
    confirmation_tag: ConfirmationTag,
}

/// This is a wrapper type, because we can't implement the storage traits on `Vec<u8>`.
#[derive(Debug, Serialize, Deserialize)]
pub struct InterimTranscriptHash(pub Vec<u8>);

// Getters
#[cfg(feature = "migration-export")]
impl PublicGroup {
    /// Get the ciphersuite.
    pub fn ciphersuite(&self) -> Ciphersuite {
        self.group_context.ciphersuite()
    }

    /// Get the group id.
    pub fn group_id(&self) -> &GroupId {
        self.group_context.group_id()
    }

    /// Get the group context.
    pub fn group_context(&self) -> &GroupContext {
        &self.group_context
    }

    /// Get confirmation tag.
    pub fn confirmation_tag(&self) -> &ConfirmationTag {
        &self.confirmation_tag
    }

    /// Deletes the [`PublicGroup`] from storage.
    pub fn delete<Storage: PublicStorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<(), Storage::Error> {
        storage.delete_tree(group_id)?;
        storage.delete_confirmation_tag(group_id)?;
        storage.delete_context(group_id)?;
        storage.delete_interim_transcript_hash(group_id)?;

        Ok(())
    }

    /// Loads the [`PublicGroup`] corresponding to a [`GroupId`] from storage.
    pub fn load<Storage: PublicStorageProvider>(
        storage: &Storage,
        group_id: &GroupId,
    ) -> Result<Option<Self>, Storage::Error> {
        let treesync = storage.tree(group_id)?;
        let proposals: Vec<(ProposalRef, QueuedProposal)> = storage.queued_proposals(group_id)?;
        let group_context = storage.group_context(group_id)?;
        let interim_transcript_hash: Option<InterimTranscriptHash> =
            storage.interim_transcript_hash(group_id)?;
        let confirmation_tag = storage.confirmation_tag(group_id)?;
        let mut proposal_store = ProposalStore::new();

        for (_ref, proposal) in proposals {
            proposal_store.add(proposal);
        }

        let build = || -> Option<Self> {
            Some(Self {
                treesync: treesync?,
                proposal_store,
                group_context: group_context?,
                interim_transcript_hash: interim_transcript_hash?.0,
                confirmation_tag: confirmation_tag?,
            })
        };

        Ok(build())
    }

    /// Returns a mutable reference to the [`ProposalStore`].
    pub(crate) fn proposal_store_mut(&mut self) -> &mut ProposalStore {
        &mut self.proposal_store
    }
}
