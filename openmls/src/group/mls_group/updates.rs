use commit_builder::CommitMessageBundle;
use errors::{ProposeSelfUpdateError, SelfUpdateError};
use openmls_traits::{signatures::Signer, storage::StorageProvider as _};

use crate::{credentials::NewSignerBundle, storage::OpenMlsProvider, treesync::LeafNodeParameters};

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

    /// Updates the own leaf node. The application can choose to update the
    /// credential, the capabilities, and the extensions by buliding the
    /// [`LeafNodeParameters`].
    ///
    /// In contrast to `self_update`, this function allows updating the
    /// signature public key in the senders leaf node. Note that `new_signer`
    /// MUST be the private key corresponding to the public key set in the
    /// `leaf_node_parameters`.
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
    pub fn self_update_with_new_signer<Provider: OpenMlsProvider, S: Signer>(
        &mut self,
        provider: &Provider,
        old_signer: &impl Signer,
        new_signer: NewSignerBundle<'_, S>,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Result<CommitMessageBundle, SelfUpdateError<Provider::StorageError>> {
        self.is_operational()?;

        let bundle = self
            .commit_builder()
            .leaf_node_parameters(leaf_node_parameters)
            .consume_proposal_store(true)
            .load_psks(provider.storage())?
            .build_with_new_signer(
                provider.rand(),
                provider.crypto(),
                old_signer,
                new_signer,
                |_| true,
            )?
            .stage_commit(provider)?;

        self.reset_aad();

        Ok(bundle)
    }

    /// Creates a proposal to update the own leaf node. Optionally, a
    /// [`LeafNode`] can be provided to update the leaf node. Note that its
    /// private key must be manually added to the key store.
    fn create_self_update_proposal_internal<Provider: OpenMlsProvider, S: Signer>(
        &mut self,
        provider: &Provider,
        old_signer: &impl Signer,
        new_signer: Option<NewSignerBundle<'_, S>>,
        mut leaf_node_parameters: LeafNodeParameters,
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

        if let Some(new_signer) = new_signer {
            if self.ciphersuite().signature_algorithm() != new_signer.signer.signature_scheme() {
                return Err(ProposeSelfUpdateError::InvalidSignerCiphersuite);
            }

            // Reconcile `leaf_node_parameters.credential_with_key` with
            // `new_signer.credential_with_key`. Mirrors the commit-path logic in
            // `CommitBuilder::build_internal`.
            if let Some(ln_cred) = leaf_node_parameters.credential_with_key() {
                if ln_cred != &new_signer.credential_with_key {
                    return Err(ProposeSelfUpdateError::InvalidLeafNodeParameters);
                }
            } else {
                leaf_node_parameters.set_credential_with_key(new_signer.credential_with_key);
            }

            own_leaf.update(
                self.ciphersuite(),
                provider,
                new_signer.signer,
                self.group_id().clone(),
                self.own_leaf_index(),
                leaf_node_parameters,
            )?;
        } else {
            own_leaf.update(
                self.ciphersuite(),
                provider,
                old_signer,
                self.group_id().clone(),
                self.own_leaf_index(),
                leaf_node_parameters,
            )?;
        }

        // Validate that the updated leaf node supports all group context extensions
        // https://validation.openmls.tech/#valn0602
        let leaf_supports_all_extensions = self
            .public_group()
            .group_context()
            .extensions()
            .iter()
            .all(|extension| own_leaf.supports_extension(&extension.extension_type()));

        if !leaf_supports_all_extensions {
            return Err(ProposeSelfUpdateError::UnsupportedGroupContextExtensions);
        }

        let update_proposal =
            self.create_update_proposal(self.framing_parameters(), own_leaf.clone(), old_signer)?;

        provider
            .storage()
            .append_own_leaf_node(self.group_id(), &own_leaf)
            .map_err(ProposeSelfUpdateError::StorageError)?;
        self.own_leaf_nodes.push(own_leaf);

        Ok(update_proposal)
    }

    fn propose_self_update_internal<Provider: OpenMlsProvider, S: Signer>(
        &mut self,
        provider: &Provider,
        old_signer: &impl Signer,
        new_signer: Option<NewSignerBundle<'_, S>>,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<Provider::StorageError>> {
        let update_proposal = self.create_self_update_proposal_internal(
            provider,
            old_signer,
            new_signer,
            leaf_node_parameters,
        )?;
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

    /// Creates a proposal to update the own leaf node. The application can
    /// choose to update the credential, the capabilities, and the extensions by
    /// building the [`LeafNodeParameters`].
    pub fn propose_self_update<Provider: OpenMlsProvider, S: Signer>(
        &mut self,
        provider: &Provider,
        signer: &S,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<Provider::StorageError>> {
        self.propose_self_update_internal(
            provider,
            signer,
            None::<NewSignerBundle<'_, S>>,
            leaf_node_parameters,
        )
    }

    /// Creates an Update proposal that rotates the sender's signature key.
    ///
    /// In contrast to [`Self::propose_self_update`], this function allows
    /// updating the signature public key of the sender's leaf node. The
    /// produced MLS message's envelope is authenticated using `old_signer`
    /// (required because the sender's current leaf in the group tree still
    /// carries the old signature key), while the new leaf embedded in the
    /// `UpdateProposal` is self-signed by `new_signer.signer` so that it
    /// validates against its own `signature_key` field at the receiver.
    ///
    /// If `leaf_node_parameters` sets `credential_with_key`, it MUST equal
    /// `new_signer.credential_with_key`. If it is not set the new-signer credential
    /// is folded in automatically.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_self_update_with_new_signer<Provider: OpenMlsProvider, S: Signer>(
        &mut self,
        provider: &Provider,
        old_signer: &impl Signer,
        new_signer: NewSignerBundle<'_, S>,
        leaf_node_parameters: LeafNodeParameters,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeSelfUpdateError<Provider::StorageError>> {
        self.propose_self_update_internal(
            provider,
            old_signer,
            Some(new_signer),
            leaf_node_parameters,
        )
    }
}
