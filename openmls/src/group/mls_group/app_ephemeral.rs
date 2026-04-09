use std::collections::BTreeSet;

use crate::{
    component::ComponentId,
    group::proposal_store::{ProposalQueue, QueuedAppEphemeralProposal},
};

impl ProposalQueue {
    /// Return an iterator over the [`QueuedAppEphemeralProposal`]s in the proposal queue,
    /// in the order they appear in the commit.
    pub fn app_ephemeral_proposals_for_component_id(
        &self,
        component_id: ComponentId,
    ) -> impl Iterator<Item = QueuedAppEphemeralProposal<'_>> {
        self.app_ephemeral_proposals()
            .filter(move |p| p.app_ephemeral_proposal().component_id() == component_id)
    }

    /// Return the list of all [`ComponentId`]s available across all
    /// [`QueuedAppEphemeralProposal`]s in the proposal queue, ordered by [`ComponentId`].
    pub fn unique_component_ids_for_app_ephemeral(&self) -> Vec<ComponentId> {
        // sort and deduplicate
        let ids: BTreeSet<_> = self
            .app_ephemeral_proposals()
            .map(|p| p.app_ephemeral_proposal().component_id())
            .collect();

        ids.into_iter().collect()
    }
}
