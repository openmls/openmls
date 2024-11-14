use commit_builder::CommitMessageBundle;
use errors::{ProposeSelfUpdateError, SelfUpdateError};
use openmls_traits::{signatures::Signer, storage::StorageProvider as _};

use crate::{storage::OpenMlsProvider, treesync::LeafNodeParameters};

use super::*;

impl MlsGroup {
    /// Updates the own leaf node. The application can choose to update the
    /// credential, the capabilities, and the extensions by buliding the
    /// [`LeafNodeParameters`].
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] (containing the
    /// commit), an optional [`MlsMessageOut`] (containing the [`Welcome`]) and
    /// the [GroupInfo]. The [`Welcome`] is [Some] when the queue of pending
    /// proposals contained add proposals The [GroupInfo] is [Some] if the group
    /// has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn self_update<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Result<CommitMessageBundle, SelfUpdateError<Provider::StorageError>> {
        self.is_operational()?;

        let bundle = self
            .commit_builder()
            .leaf_node_parameters(leaf_node_parameters)
            .consume_proposal_store(true)
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .stage_commit(provider)?;

        self.reset_aad();

        Ok(bundle)
    }

    /// Creates a proposal to update the own leaf node. Optionally, a
    /// [`LeafNode`] can be provided to update the leaf node. Note that its
    /// private key must be manually added to the key store.
    fn _propose_self_update<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        leaf_node_parmeters: LeafNodeParameters,
    ) -> Result<AuthenticatedContent, ProposeSelfUpdateError<Provider::StorageError>> {
        self.is_operational()?;

        // Here we clone our own leaf to rekey it such that we don't change the
        // tree.
        // The new leaf node will be applied later when the proposal is
        // committed.
        let mut own_leaf = self
            .public_group()
            .leaf(self.own_leaf_index())
            .ok_or_else(|| LibraryError::custom("The tree is broken. Couldn't find own leaf."))?
            .clone();

        own_leaf.update(
            self.ciphersuite(),
            provider,
            signer,
            self.group_id().clone(),
            self.own_leaf_index(),
            leaf_node_parmeters,
        )?;

        let update_proposal =
            self.create_update_proposal(self.framing_parameters(), own_leaf.clone(), signer)?;

        provider
            .storage()
            .append_own_leaf_node(self.group_id(), &own_leaf)
            .map_err(ProposeSelfUpdateError::StorageError)?;
        self.own_leaf_nodes.push(own_leaf);

        Ok(update_proposal)
    }

    /// Creates a proposal to update the own leaf node. The application can
    /// choose to update the credential, the capabilities, and the extensions by
    /// building the [`LeafNodeParameters`].
    pub fn propose_self_update<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<Provider::StorageError>> {
        let update_proposal = self._propose_self_update(provider, signer, leaf_node_parameters)?;
        let proposal = QueuedProposal::from_authenticated_content_by_ref(
            self.ciphersuite(),
            provider.crypto(),
            update_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference();
        provider
            .storage()
            .queue_proposal(self.group_id(), &proposal_ref, &proposal)
            .map_err(ProposeSelfUpdateError::StorageError)?;
        self.proposal_store_mut().add(proposal);

        let mls_message = self.content_to_mls_message(update_proposal, provider)?;

        self.reset_aad();
        Ok((mls_message, proposal_ref))
    }
}
