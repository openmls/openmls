use core_group::create_commit_params::CreateCommitParams;

use super::*;

impl ManagedGroup {
    /// Updates the own leaf node
    ///
    /// A [`KeyPackageBundle`](crate::prelude::KeyPackageBundle) can optionally
    /// be provided. If not, a new one will be created on the fly.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] and an optional [`Welcome`].
    /// The [Welcome] is [Some] when the queue of pending proposals contained add proposals.
    pub fn self_update(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<(MlsMessageOut, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals. If a `KeyPackageBundle` was passed
        // in, use it to create an update proposal by value. TODO #141
        let (commit, welcome_option, kpb_option) = match key_package_bundle_option {
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

        // Take the new KeyPackageBundle and save it for later
        let kpb = kpb_option.ok_or_else(|| {
            ManagedGroupError::LibraryError(
                "We didn't get a key package for a full commit on self update.".into(),
            )
        })?;

        self.own_kpbs.push(kpb);

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.plaintext_to_mls_message(commit, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, welcome_option))
    }

    /// Creates a proposal to update the own leaf node
    pub fn propose_self_update(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        key_package_bundle_option: Option<KeyPackageBundle>,
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let tree = self.group.tree();
        let existing_key_package = tree.own_key_package();
        let key_package_bundle = match key_package_bundle_option {
            Some(kpb) => kpb,
            None => {
                KeyPackageBundlePayload::from_rekeyed_key_package(existing_key_package, backend)?
                    .sign(backend, &credential_bundle)?
            }
        };

        let update_proposal = self.group.create_update_proposal(
            self.framing_parameters(),
            &credential_bundle,
            key_package_bundle.key_package().clone(),
            backend,
        )?;
        drop(tree);

        self.own_kpbs.push(key_package_bundle);

        let mls_message = self.plaintext_to_mls_message(update_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }
}
