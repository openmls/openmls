use std::collections::HashSet;

use crate::{
    binary_tree::LeafNodeIndex,
    error::LibraryError,
    framing::Sender,
    group::proposal_store::ProposalQueue,
    messages::proposals::{AddProposal, ExternalInitProposal, Proposal, ProposalType},
    schedule::psk::PreSharedKeyId,
};

use super::*;

/// This struct contain the return values of the `apply_proposals()` function
#[derive(Debug)]
pub(crate) struct ApplyProposalsValues {
    pub(crate) path_required: bool,
    pub(crate) self_removed: bool,
    pub(crate) invitation_list: Vec<(LeafNodeIndex, AddProposal)>,
    pub(crate) presharedkeys: Vec<PreSharedKeyId>,
    pub(crate) external_init_proposal_option: Option<ExternalInitProposal>,
    pub(crate) extensions: Option<Extensions>,
}

impl ApplyProposalsValues {
    /// This function creates a `HashSet` of node indexes of the new nodes that
    /// were added to the tree. The `HashSet` will be querried by the
    /// `resolve()` function to filter out those nodes from the resolution.
    pub(crate) fn exclusion_list(&self) -> HashSet<&LeafNodeIndex> {
        // Collect the new leaves' indexes so we can filter them out in the resolution
        // later
        let new_leaves_indexes: HashSet<&LeafNodeIndex> = self
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
/// [`LeafNode`]s corresponding to updates or commits sent in the
/// current epoch.
///
/// If an `own_leaf_index` is provided, `self_removed` in the returned
/// `ApplyProposalValues` is set to `true` if that leaf index is targeted by a
/// Remove proposal.
///
/// Returns an error if the proposals have not been validated before.
impl PublicGroupDiff<'_> {
    pub(crate) fn apply_proposals(
        &mut self,
        proposal_queue: &ProposalQueue,
        own_leaf_index: impl Into<Option<LeafNodeIndex>>,
    ) -> Result<ApplyProposalsValues, LibraryError> {
        log::debug!("Applying proposal");
        let mut self_removed = false;

        // Process external init proposals. We do this before the removes, so we
        // know that removing "ourselves" (i.e. removing the group member in the
        // same leaf as we are in) is valid in this case. We only care about the
        // first proposal and ignore all others.
        let external_init_proposal_option = proposal_queue
            .filtered_by_type(ProposalType::ExternalInit)
            .next()
            .and_then(|queued_proposal| {
                if let Proposal::ExternalInit(external_init_proposal) = queued_proposal.proposal() {
                    Some(external_init_proposal.clone())
                } else {
                    None
                }
            });

        // Process updates first
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Update) {
            if let Proposal::Update(update_proposal) = queued_proposal.proposal() {
                // Check if this is our own update.
                let sender = queued_proposal.sender();
                // Only members can send update proposals
                // ValSem112
                let sender_index = match sender {
                    Sender::Member(sender_index) => *sender_index,
                    // This should not happen with validated proposals
                    _ => return Err(LibraryError::custom("Update proposal from non-member")),
                };
                let leaf_node = update_proposal.leaf_node().clone();
                self.diff.update_leaf(leaf_node, sender_index);
            }
        }

        // Process removes
        let own_leaf_index = own_leaf_index.into();
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Remove) {
            if let Proposal::Remove(remove_proposal) = queued_proposal.proposal() {
                // Check if we got removed from the group
                match own_leaf_index {
                    Some(leaf_index) if remove_proposal.removed() == leaf_index => {
                        self_removed = true
                    }
                    _ => (),
                };
                // Blank the direct path of the removed member
                self.diff.blank_leaf(remove_proposal.removed());
            }
        }

        // Process adds
        let add_proposals = proposal_queue
            .filtered_by_type(ProposalType::Add)
            .filter_map(|queued_proposal| {
                if let Proposal::Add(add_proposal) = queued_proposal.proposal() {
                    Some(add_proposal)
                } else {
                    None
                }
            });

        // Extract KeyPackages from proposals
        let mut invitation_list = Vec::new();
        for add_proposal in add_proposals {
            // XXX: There are too many clones here.
            let leaf_node = add_proposal.key_package.leaf_node();
            let leaf_index = self
                .diff
                .add_leaf(leaf_node.clone())
                // TODO #810
                .map_err(|_| LibraryError::custom("Tree full: cannot add more members"))?;
            invitation_list.push((leaf_index, add_proposal.clone()))
        }

        // Process PSK proposals
        let presharedkeys: Vec<PreSharedKeyId> = proposal_queue
            .filtered_by_type(ProposalType::PreSharedKey)
            .filter_map(|queued_proposal| {
                if let Proposal::PreSharedKey(psk_proposal) = queued_proposal.proposal() {
                    Some(psk_proposal.clone().into_psk_id())
                } else {
                    None
                }
            })
            .collect();

        // apply group context extension proposal
        let extensions = proposal_queue
            .filtered_by_type(ProposalType::GroupContextExtensions)
            .find_map(|queued_proposal| match queued_proposal.proposal() {
                Proposal::GroupContextExtensions(extensions) => {
                    Some(extensions.extensions().clone())
                }
                _ => None,
            });

        let proposals_require_path = proposal_queue
            .queued_proposals()
            .any(|p| p.proposal().is_path_required());

        // This flag determines if the commit requires a path. A path is required if:
        // * none of the proposals require a path
        // * (or) it is an external commit
        // * (or) the commit is empty which implicitly means it's a self-update
        let path_required = proposals_require_path
            // The fact that this is some implies that there's an external init proposal.
            || external_init_proposal_option.is_some()
            || proposal_queue.is_empty();

        Ok(ApplyProposalsValues {
            path_required,
            self_removed,
            invitation_list,
            presharedkeys,
            external_init_proposal_option,
            extensions,
        })
    }
}
