//! MLS group context extensions
//!
//! Contains all the method related to modifying a group's extensions

use std::iter;

use openmls_traits::signatures::Signer;

use crate::{
    messages::group_info::GroupInfo,
    prelude::{
        create_commit_params::CreateCommitParams, hash_ref::ProposalRef,
        ProposeGroupContextExtensionError,
    },
};

use super::*;

impl MlsGroup {
    /// Creates proposals to update extensions of the group. This replaces the existing extensions
    /// of a group and does not merge them.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_extensions(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        extensions: Extensions,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeGroupContextExtensionError> {
        self.is_operational()?;

        let gce_proposal = self.group.create_group_context_ext_proposal(
            self.framing_parameters(),
            extensions,
            self.pending_proposals(),
            signer,
        )?;
        let proposal = QueuedProposal::from_authenticated_content(
            self.ciphersuite(),
            backend,
            gce_proposal.clone(),
            ProposalOrRefType::Proposal,
        )?;
        let reference = proposal.proposal_reference();

        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(gce_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, reference))
    }

    /// Updates the extensions of the group
    ///
    /// This operation results in a Commit with a `path`, i.e. it includes an
    /// update of the committer's leaf [KeyPackage].
    ///
    /// If successful, it returns a tupple where the first element
    /// contains the commit and the second an optional [GroupInfo] that
    /// will be [Some] if the group has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    pub fn update_extensions<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        extensions: Extensions,
    ) -> Result<(MlsMessageOut, Option<GroupInfo>), UpdateExtensionsError<KeyStore::Error>> {
        self.is_operational()?;
        self.group
            .members_supports_extensions(&extensions, iter::empty())?;
        let proposal =
            Proposal::GroupContextExtensions(GroupContextExtensionProposal::new(extensions));
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .inline_proposals(vec![proposal])
            .build();
        let create_commit_result = self.group.create_commit(params, backend, signer)?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.content_to_mls_message(create_commit_result.commit, backend)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();
        Ok((mls_messages, create_commit_result.group_info))
    }

    /// Get a group's [`Extension`].
    pub fn group_context_extensions(&self) -> &Extensions {
        self.group.context().extensions()
    }
}
