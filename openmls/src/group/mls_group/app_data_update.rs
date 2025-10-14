use super::staged_commit::StagedCommitState;
use crate::{
    extensions::{AppDataDictionary, ComponentId},
    group::{ProposalQueue, QueuedAppDataUpdateProposal},
};

impl ProposalQueue {
    /// Iterate over the [`QueuedAppDataUpdateProposal`]s for a given [`ComponentId`].
    pub fn app_data_update_proposals_for_id(
        &self,
        component_id: ComponentId,
    ) -> impl Iterator<Item = QueuedAppDataUpdateProposal<'_>> {
        self.app_data_update_proposals().filter(move |proposal| {
            proposal.app_data_update_proposal().component_id() == component_id
        })
    }
}

impl StagedCommitState {
    /// Retrieve a mutable reference to the [`AppDataDictionary`] in the group context extensions,
    /// if it exists.
    pub fn app_data_dictionary(&mut self) -> Option<&mut AppDataDictionary> {
        self.staged_diff_mut()
            .group_context_mut()
            .extensions_mut()
            .app_data_dictionary_mut()
            .map(|extension| extension.dictionary_mut())
    }
}
/*
impl StagedCommit {
    /// Return a mutable reference to the \`AppDataDictionary\` extension, if available.
    pub fn as_app_data_update_proposals_and_dictionary(
        &mut self,
        component_id: ComponentId,
    ) -> Option<(
        impl Iterator<Item = QueuedAppDataUpdateProposal<'_>>,
        &mut AppDataDictionary,
    )> {
        let app_data_updates = self
            .staged_proposal_queue
            .app_data_update_proposals_for_id(component_id);
        self.state
            .app_data_dictionary()
            .map(|dictionary| (app_data_updates, dictionary))
    }
}
*/
