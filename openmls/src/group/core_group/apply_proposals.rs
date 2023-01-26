use std::collections::HashSet;

use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    error::LibraryError,
    framing::Sender,
    group::errors::ApplyProposalsError,
    messages::proposals::{AddProposal, Proposal, ProposalType},
    schedule::InitSecret,
    treesync::{diff::TreeSyncDiff, node::leaf_node::OpenMlsLeafNode},
};

use super::*;

/// This struct contain the return values of the `apply_proposals()` function
pub(crate) struct ApplyProposalsValues {
    pub(crate) path_required: bool,
    pub(crate) self_removed: bool,
    pub(crate) invitation_list: Vec<(LeafNodeIndex, AddProposal)>,
    pub(crate) presharedkeys: Vec<PreSharedKeyId>,
    pub(crate) external_init_secret_option: Option<InitSecret>,
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
/// [`OpenMlsLeafNode`]s corresponding to updates or commits sent in the
/// current epoch.
///
/// Returns an error if the proposals have not been validated before.
impl CoreGroup {
    pub(crate) fn apply_proposals(
        &self,
        diff: &mut TreeSyncDiff,
        backend: &impl OpenMlsCryptoProvider,
        proposal_queue: &ProposalQueue,
        leaf_nodes: &[OpenMlsLeafNode],
        own_leaf_index: impl Into<Option<LeafNodeIndex>>,
    ) -> Result<ApplyProposalsValues, ApplyProposalsError> {
        log::debug!("Applying proposal");
        let mut self_removed = false;
        let mut external_init_secret_option = None;

        // Process external init proposals. We do this before the removes, so we
        // know that removing "ourselves" (i.e. removing the group member in the
        // same leaf as we are in) is valid in this case. We only care about the
        // first proposal and ignore all others.
        if let Some(queued_proposal) = proposal_queue
            .filtered_by_type(ProposalType::ExternalInit)
            .next()
        {
            if let Proposal::ExternalInit(external_init_proposal) = queued_proposal.proposal() {
                // Decrypt the content and derive the external init secret.
                let external_priv = self
                    .group_epoch_secrets()
                    .external_secret()
                    .derive_external_keypair(backend.crypto(), self.ciphersuite())
                    .private
                    .into();
                external_init_secret_option = Some(InitSecret::from_kem_output(
                    backend,
                    self.ciphersuite(),
                    self.version(),
                    &external_priv,
                    external_init_proposal.kem_output(),
                )?)
            }
        }

        let own_leaf_index = own_leaf_index.into();

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
                    _ => return Err(LibraryError::custom("Update proposal from non-member").into()),
                };
                let leaf_node: OpenMlsLeafNode = match own_leaf_index {
                    Some(leaf_index) if leaf_index == sender_index => {
                        let own_leaf_node = match leaf_nodes
                            .iter()
                            .find(|&leaf_node| leaf_node.leaf_node() == update_proposal.leaf_node())
                        {
                            Some(leaf_node) => leaf_node,
                            // We lost the LeafNode apparently
                            None => return Err(ApplyProposalsError::MissingLeafNode),
                        };
                        own_leaf_node.clone()
                    }
                    _ => update_proposal.leaf_node().clone().into(),
                };
                diff.update_leaf(leaf_node, sender_index);
            }
        }

        // Process removes
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Remove) {
            if let Proposal::Remove(remove_proposal) = queued_proposal.proposal() {
                // Check if we got removed from the group
                if remove_proposal.removed() == self.own_leaf_index() {
                    self_removed = true;
                }
                // Blank the direct path of the removed member
                diff.blank_leaf(remove_proposal.removed());
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
            let leaf_index = diff
                .add_leaf(leaf_node.clone().into())
                // TODO #810
                .map_err(|_| LibraryError::custom("Tree full: cannot add more members"))?;
            invitation_list.push((leaf_index, add_proposal.clone()))
        }

        // Process PSK proposals
        let presharedkeys: Vec<PreSharedKeyId> = proposal_queue
            .filtered_by_type(ProposalType::Presharedkey)
            .filter_map(|queued_proposal| {
                if let Proposal::PreSharedKey(psk_proposal) = queued_proposal.proposal() {
                    Some(psk_proposal.clone().into_psk_id())
                } else {
                    None
                }
            })
            .collect();

        let proposals_require_path = proposal_queue
            .queued_proposals()
            .any(|p| p.proposal().is_path_required());

        // This flag determines if the commit requires a path. A path is required if:
        // * none of the proposals require a path
        // * (or) it is an external commit
        // * (or) the commit is empty which implicitly means it's a self-update
        let path_required = proposals_require_path
            // The fact that this is some implies that there's an external init proposal.
            || external_init_secret_option.is_some()
            || proposal_queue.is_empty();

        Ok(ApplyProposalsValues {
            path_required,
            self_removed,
            invitation_list,
            presharedkeys,
            external_init_secret_option,
        })
    }
}
