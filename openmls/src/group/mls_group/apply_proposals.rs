use std::collections::HashSet;

use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    binary_tree::LeafIndex,
    messages::proposals::{AddProposal, ProposalType},
    prelude::{KeyPackage, KeyPackageBundle, KeyPackageBundlePayload},
    schedule::{PreSharedKeyId, PreSharedKeys},
    treesync::{diff::TreeSyncDiff, node::Node, TreeSyncError},
};

use super::{
    proposals::{CreationProposalQueue, StagedProposalQueue},
    MlsGroup,
};

/// This struct contain the return values of the `apply_proposals()` function
pub struct ApplyProposalsValues {
    pub path_required: bool,
    pub self_removed: bool,
    pub invitation_list: Vec<(LeafIndex, AddProposal)>,
    pub presharedkeys: PreSharedKeys,
}

impl ApplyProposalsValues {
    /// This function creates a `HashSet` of node indexes of the new nodes that
    /// were added to the tree. The `HashSet` will be querried by the
    /// `resolve()` function to filter out those nodes from the resolution.
    pub fn exclusion_list(&self) -> HashSet<&LeafIndex> {
        // Collect the new leaves' indexes so we can filter them out in the resolution
        // later
        let new_leaves_indexes: HashSet<&LeafIndex> = self
            .invitation_list
            .iter()
            .map(|(index, _)| index)
            .collect();
        new_leaves_indexes
    }
}

/// Applies a list of proposals from a Commit to the tree.
/// `proposal_queue` is the queue of proposals received or sent in the
/// current epoch `updates_key_package_bundles` is the list of own
/// KeyPackageBundles corresponding to updates or commits sent in the
/// current epoch
impl MlsGroup {
    pub(crate) fn apply_proposals(
        &self,
        // FIXME: We can probably just return the diff or the staged diff here.
        diff: &mut TreeSyncDiff,
        backend: &impl OpenMlsCryptoProvider,
        proposal_queue: CreationProposalQueue,
        // FIXME: Should this be here? If it's my own update, I need to include
        // a path anyway, so we can just filter out own updates, righ?
        key_package_bundle_payload_option: Option<KeyPackageBundlePayload>,
    ) -> Result<ApplyProposalsValues, TreeSyncError> {
        log::debug!("Applying proposal");
        let mut has_updates = false;
        let mut has_removes = false;
        let mut self_removed = false;

        // Process updates first
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Update) {
            has_updates = true;
            // Unwrapping here is safe because we know the proposal type
            let update_proposal = &queued_proposal.proposal().as_update().unwrap();
            // Check if this is our own update.
            diff.update_leaf(
                update_proposal.key_package().clone(),
                queued_proposal.sender().to_leaf_index().as_u32(),
            )?;
            // FIXME: Potentially process own update here (see comment above.)
        }

        // Process removes
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Remove) {
            has_removes = true;
            // Unwrapping here is safe because we know the proposal type
            let remove_proposal = &queued_proposal.proposal().as_remove().unwrap();
            let removed = LeafIndex::from(remove_proposal.removed());
            // Check if we got removed from the group
            if removed == self.tree().own_leaf_index() {
                self_removed = true;
            }
            // Blank the direct path of the removed member
            diff.blank_leaf(removed)?;
        }

        // Process adds
        let add_proposals: Vec<AddProposal> = proposal_queue
            .filtered_by_type(ProposalType::Add)
            .map(|queued_proposal| {
                let proposal = &queued_proposal.proposal();
                // Unwrapping here is safe because we know the proposal type
                proposal.as_add().unwrap()
            })
            .collect();

        // Extract KeyPackages from proposals
        let mut invitation_list = Vec::new();
        for add_proposal in &add_proposals {
            let leaf_index = diff.add_leaf(add_proposal.key_package().clone())?;
            invitation_list.push((leaf_index, add_proposal.clone()))
        }

        // Process PSK proposals
        let psks: Vec<PreSharedKeyId> = proposal_queue
            .filtered_by_type(ProposalType::Presharedkey)
            .map(|queued_proposal| {
                // FIXME: remove unwrap
                // Unwrapping here is safe because we know the proposal type
                let psk_proposal = queued_proposal.proposal().as_presharedkey().unwrap();
                psk_proposal.into_psk_id()
            })
            .collect();

        let presharedkeys = PreSharedKeys { psks: psks.into() };

        // Determine if Commit needs a path field
        let path_required = has_updates || has_removes;

        Ok(ApplyProposalsValues {
            path_required,
            self_removed,
            invitation_list,
            presharedkeys,
        })
    }

    /// Applies a list of staged proposals from a Commit to the tree.
    /// `proposal_queue` is the queue of proposals received or sent in the
    /// current epoch `updates_key_package_bundles` is the list of own
    /// KeyPackageBundles corresponding to updates or commits sent in the
    /// current epoch
    pub fn apply_staged_proposals(
        &self,
        diff: &mut TreeSyncDiff,
        backend: &impl OpenMlsCryptoProvider,
        proposal_queue: &StagedProposalQueue,
        updates_key_package_bundles: &[KeyPackageBundle],
    ) -> Result<ApplyProposalsValues, TreeSyncError> {
        log::debug!("Applying proposal");
        let mut has_updates = false;
        let mut has_removes = false;
        let mut self_removed = false;

        // Process updates first
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Update) {
            has_updates = true;
            // Unwrapping here is safe because we know the proposal type
            let update_proposal = &queued_proposal.proposal().as_update().unwrap();
            // Check if this is our own update.
            diff.update_leaf(
                update_proposal.key_package().clone(),
                queued_proposal.sender().to_leaf_index().as_u32(),
            )?;
            // FIXME: Potentially process own update here (see comment above.)
        }

        // Process removes
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Remove) {
            has_removes = true;
            // Unwrapping here is safe because we know the proposal type
            let remove_proposal = &queued_proposal.proposal().as_remove().unwrap();
            let removed = LeafIndex::from(remove_proposal.removed());
            // Check if we got removed from the group
            if removed == self.tree().own_leaf_index() {
                self_removed = true;
            }
            // Blank the direct path of the removed member
            diff.blank_leaf(removed)?;
        }

        // Process adds
        let add_proposals: Vec<AddProposal> = proposal_queue
            .filtered_by_type(ProposalType::Add)
            .map(|queued_proposal| {
                let proposal = &queued_proposal.proposal();
                // Unwrapping here is safe because we know the proposal type
                proposal.as_add().unwrap()
            })
            .collect();

        // Extract KeyPackages from proposals
        let mut invitation_list = Vec::new();
        for add_proposal in &add_proposals {
            let leaf_index = diff.add_leaf(add_proposal.key_package().clone())?;
            invitation_list.push((leaf_index, add_proposal.clone()))
        }

        // Process PSK proposals
        let psks: Vec<PreSharedKeyId> = proposal_queue
            .filtered_by_type(ProposalType::Presharedkey)
            .map(|queued_proposal| {
                // FIXME: remove unwrap
                // Unwrapping here is safe because we know the proposal type
                let psk_proposal = queued_proposal.proposal().as_presharedkey().unwrap();
                psk_proposal.into_psk_id()
            })
            .collect();

        let presharedkeys = PreSharedKeys { psks: psks.into() };

        // Determine if Commit needs a path field
        let path_required = has_updates || has_removes;

        Ok(ApplyProposalsValues {
            path_required,
            self_removed,
            invitation_list,
            presharedkeys,
        })
    }
}
