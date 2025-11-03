use super::proposal_store::{ProposalQueue, QueuedAppEphemeralProposal};
use super::staged_commit::StagedCommitState;

use crate::extensions::{AppDataDictionaryExtension, ComponentId};
use crate::prelude::ProposalType;

impl StagedCommitState {
    /// Return a mutable reference to the [`AppDataDictionaryExtension`], if it exists
    pub fn app_data_dictionary_mut(&mut self) -> Option<&mut AppDataDictionaryExtension> {
        self.group_context_mut()
            .extensions_mut()
            .app_data_dictionary_mut()
    }
}

impl ProposalQueue {
    /// Return an iterator over the [`QueuedAppEphemeralProposal`]s in the proposal queue,
    /// in the order they appear in the commit.
    pub fn app_ephemeral_proposals_for_component_id(
        &self,
        component_id: ComponentId,
    ) -> impl Iterator<Item = QueuedAppEphemeralProposal<'_>> {
        self.app_ephemeral_proposals()
            .filter(move |p| p.app_ephemeral_proposal().component_id == component_id)
    }
}
