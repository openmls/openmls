use core_group::create_commit_params::CreateCommitParams;
use tls_codec::Serialize;

use super::*;

impl MlsGroup {
    /// Updates the own leaf node.
    ///
    /// A [`KeyPackageBundle`](crate::key_packages::KeyPackageBundle) can optionally
    /// be provided. If not, a new one will be created on the fly.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] and an optional [`Welcome`].
    /// The [Welcome] is [Some] when the queue of pending proposals contained add proposals.
    ///
    /// Returns an error if there is a pending commit.
    pub fn self_update(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<(MlsMessageOut, Option<Welcome>), SelfUpdateError> {
        self.is_operational()?;

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .ok_or(SelfUpdateError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals. If a `KeyPackageBundle` was passed
        // in, use it to create an update proposal by value. TODO #751
        let create_commit_result = match key_package_bundle_option {
            Some(kpb) => {
                let update_proposal = Proposal::Update(UpdateProposal {
                    key_package: kpb.key_package().clone(),
                });
                let params = CreateCommitParams::builder()
                    .framing_parameters(self.framing_parameters())
                    .credential_bundle(&credential_bundle)
                    .proposal_store(&self.proposal_store)
                    .inline_proposals(vec![update_proposal])
                    .build();
                self.group.create_commit(params, backend)?
            }
            None => {
                let params = CreateCommitParams::builder()
                    .framing_parameters(self.framing_parameters())
                    .credential_bundle(&credential_bundle)
                    .proposal_store(&self.proposal_store)
                    .build();
                self.group.create_commit(params, backend)?
            }
        };

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.plaintext_to_mls_message(create_commit_result.commit, backend)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, create_commit_result.welcome_option))
    }

    /// Creates a proposal to update the own leaf node.
    pub fn propose_self_update(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<MlsMessageOut, ProposeSelfUpdateError> {
        self.is_operational()?;

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .ok_or(ProposeSelfUpdateError::NoMatchingCredentialBundle)?;

        let tree = self.group.treesync();
        let existing_key_package = tree
            .own_leaf_node()
            .map_err(|_| LibraryError::custom("Expected own leaf to exist"))?
            .key_package();
        let key_package_bundle = match key_package_bundle_option {
            Some(kpb) => kpb,
            None => {
                KeyPackageBundlePayload::from_rekeyed_key_package(existing_key_package, backend)
                    .map_err(LibraryError::unexpected_crypto_error)?
                    .sign(backend, &credential_bundle)?
            }
        };

        let update_proposal = self.group.create_update_proposal(
            self.framing_parameters(),
            &credential_bundle,
            key_package_bundle.key_package().clone(),
            backend,
        )?;

        self.own_kpbs.push(key_package_bundle);
        self.proposal_store.add(QueuedProposal::from_mls_plaintext(
            self.ciphersuite(),
            backend,
            update_proposal.clone(),
        )?);

        let mls_message = self.plaintext_to_mls_message(update_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }
}
