use core_group::create_commit_params::CreateCommitParams;
use openmls_traits::signatures::Signer;

use crate::{messages::group_info::GroupInfo, treesync::LeafNode, versions::ProtocolVersion};

use super::*;

impl MlsGroup {
    /// Updates the own leaf node.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] (containing the
    /// commit), an optional [`MlsMessageOut`] (containing the [`Welcome`]) and the [GroupInfo].
    /// The [Welcome] is [Some] when the queue of pending proposals contained
    /// add proposals
    /// The [GroupInfo] is [Some] if the group has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    ///
    /// TODO #1208 : The caller should be able to optionally provide a
    /// [`LeafNode`] here, so that things like extensions can be changed via
    /// commit.
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        SelfUpdateError<KeyStore::Error>,
    > {
        self.is_operational()?;

        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .build();
        // Create Commit over all proposals.
        // TODO #751
        let create_commit_result = self.group.create_commit(params, provider, signer)?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((
            mls_message,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }

    /// Creates a proposal to update the own leaf node. Optionally, a
    /// [`LeafNode`] can be provided to update the leaf node. Note that its
    /// private key must be manually added to the key store.
    fn _propose_self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        leaf_node: Option<LeafNode>,
    ) -> Result<AuthenticatedContent, ProposeSelfUpdateError<KeyStore::Error>> {
        self.is_operational()?;

        // Here we clone our own leaf to rekey it such that we don't change the
        // tree.
        // The new leaf node will be applied later when the proposal is
        // committed.
        let mut own_leaf = self
            .group
            .public_group()
            .leaf(self.own_leaf_index())
            .ok_or_else(|| LibraryError::custom("The tree is broken. Couldn't find own leaf."))?
            .clone();
        if let Some(leaf) = leaf_node {
            own_leaf.update_and_re_sign(
                None,
                leaf,
                self.group_id().clone(),
                self.own_leaf_index(),
                signer,
            )?
        } else {
            let keypair = own_leaf.rekey(
                self.group_id(),
                self.own_leaf_index(),
                self.ciphersuite(),
                ProtocolVersion::default(), // XXX: openmls/openmls#1065
                provider,
                signer,
            )?;
            // TODO #1207: Move to the top of the function.
            keypair
                .write_to_key_store(provider.key_store())
                .map_err(ProposeSelfUpdateError::KeyStoreError)?;
        };

        let update_proposal = self.group.create_update_proposal(
            self.framing_parameters(),
            own_leaf.clone(),
            signer,
        )?;

        self.own_leaf_nodes.push(own_leaf);

        Ok(update_proposal)
    }

    /// Creates a proposal to update the own leaf node.
    pub fn propose_self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        leaf_node: Option<LeafNode>,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<KeyStore::Error>> {
        let update_proposal = self._propose_self_update(provider, signer, leaf_node)?;
        let proposal = QueuedProposal::from_authenticated_content_by_ref(
            self.ciphersuite(),
            provider.crypto(),
            update_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference();
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(update_proposal, provider)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }

    /// Creates a proposal to update the own leaf node.
    pub fn propose_self_update_by_value<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        leaf_node: Option<LeafNode>,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<KeyStore::Error>> {
        let update_proposal = self._propose_self_update(provider, signer, leaf_node)?;
        let proposal = QueuedProposal::from_authenticated_content_by_value(
            self.ciphersuite(),
            provider.crypto(),
            update_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference();
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(update_proposal, provider)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }
}
