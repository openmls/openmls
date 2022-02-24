use std::collections::HashSet;

use openmls_traits::OpenMlsCryptoProvider;

use crate::{
    binary_tree::LeafIndex,
    error::LibraryError,
    framing::Sender,
    group::errors::ApplyProposalsError,
    key_packages::KeyPackageBundle,
    messages::proposals::{AddProposal, Proposal, ProposalType},
    schedule::{psk::*, InitSecret},
    treesync::{diff::TreeSyncDiff, node::leaf_node::LeafNode},
};

use super::*;

/// This struct contain the return values of the `apply_proposals()` function
pub(crate) struct ApplyProposalsValues {
    pub(crate) path_required: bool,
    pub(crate) self_removed: bool,
    pub(crate) invitation_list: Vec<(LeafIndex, AddProposal)>,
    pub(crate) presharedkeys: PreSharedKeys,
    pub(crate) external_init_secret_option: Option<InitSecret>,
}

impl ApplyProposalsValues {
    /// This function creates a `HashSet` of node indexes of the new nodes that
    /// were added to the tree. The `HashSet` will be querried by the
    /// `resolve()` function to filter out those nodes from the resolution.
    pub(crate) fn exclusion_list(&self) -> HashSet<&LeafIndex> {
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
/// current epoch.
///
/// Returns an error if the proposals have not been validated before.
impl CoreGroup {
    pub(crate) fn apply_proposals(
        &self,
        diff: &mut TreeSyncDiff,
        backend: &impl OpenMlsCryptoProvider,
        proposal_queue: &ProposalQueue,
        key_package_bundles: &[KeyPackageBundle],
    ) -> Result<ApplyProposalsValues, ApplyProposalsError> {
        log::debug!("Applying proposal");
        let mut has_updates = false;
        let mut has_removes = false;
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
                    self.mls_version,
                    &external_priv,
                    external_init_proposal.kem_output(),
                )?)
            }
        }

        // Process updates first
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Update) {
            has_updates = true;
            if let Proposal::Update(update_proposal) = queued_proposal.proposal() {
                // Check if this is our own update.
                let sender = queued_proposal.sender();
                // Only members can send update proposals
                // ValSem112
                let hash_ref = match sender {
                    Sender::Member(hash_ref) => hash_ref,
                    // This should not happen with validated proposals
                    _ => return Err(LibraryError::custom("Update proposal from non-member").into()),
                };
                let sender_index = self
                    .sender_index(hash_ref)
                    // This should not happen with validated proposals
                    .map_err(|_| LibraryError::custom("Update proposal from non-member"))?;
                let leaf_node: LeafNode = if sender_index == self.tree.own_leaf_index() {
                    let own_kpb = match key_package_bundles
                        .iter()
                        .find(|&kpb| kpb.key_package() == update_proposal.key_package())
                    {
                        Some(kpb) => kpb,
                        // We lost the KeyPackageBundle apparently
                        None => return Err(ApplyProposalsError::MissingKeyPackageBundle),
                    };
                    LeafNode::new_from_bundle(own_kpb.clone(), backend.crypto())
                } else {
                    LeafNode::new(update_proposal.key_package().clone(), backend.crypto())
                }?;
                diff.update_leaf(leaf_node, sender_index)
                    .map_err(|_| LibraryError::custom("Update proposal from non-member"))?;
            }
        }

        // Process removes
        for queued_proposal in proposal_queue.filtered_by_type(ProposalType::Remove) {
            has_removes = true;
            if let Proposal::Remove(remove_proposal) = queued_proposal.proposal() {
                // Check if we got removed from the group
                if let Some(own_kpr) = self.key_package_ref() {
                    if remove_proposal.removed() == own_kpr {
                        self_removed = true;
                    }
                }
                // Blank the direct path of the removed member
                if let Ok(removed_index) = self.sender_index(remove_proposal.removed()) {
                    diff.blank_leaf(removed_index)
                        // The remove proposals were validated before, so this should not happen
                        .map_err(|_| LibraryError::custom("Removed member not in tree"))?;
                }
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
            let leaf_index = diff
                .add_leaf(add_proposal.key_package().clone(), backend.crypto())
                // TODO #810
                .map_err(|_| LibraryError::custom("Tree full: cannot add more members"))?;
            invitation_list.push((leaf_index, add_proposal.clone()))
        }

        // Process PSK proposals
        let psks: Vec<PreSharedKeyId> = proposal_queue
            .filtered_by_type(ProposalType::Presharedkey)
            .filter_map(|queued_proposal| {
                if let Proposal::PreSharedKey(psk_proposal) = queued_proposal.proposal() {
                    Some(psk_proposal.clone().into_psk_id())
                } else {
                    None
                }
            })
            .collect();

        let presharedkeys = PreSharedKeys { psks: psks.into() };

        // This flag determines if the commit requires a path. A path is
        // required if the commit is empty, i.e. if it doesn't contain any
        // proposals or if it is a "full" commit. A commit is full if it refers
        // to proposal types other than Add, PreSharedKey and/or ReInit
        // proposals.
        let path_required = has_updates
            || has_removes
            // The fact that this is some implies that there's an external init
            // proposal.
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
