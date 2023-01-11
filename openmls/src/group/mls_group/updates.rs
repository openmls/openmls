use core_group::create_commit_params::CreateCommitParams;
use tls_codec::Serialize;

use crate::{ciphersuite::HpkePublicKey, versions::ProtocolVersion};

use super::*;

impl MlsGroup {
    /// Updates the own leaf node.
    ///
    /// An [`HpkePublicKey`] can optionally be provided.
    /// If not, a new one will be created on the fly.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] (containing the
    /// commit) and an optional [`MlsMessageOut`] (containing the [`Welcome`]).
    /// The [Welcome] is [Some] when the queue of pending proposals contained
    /// add proposals
    ///
    /// Returns an error if there is a pending commit.
    pub fn self_update(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        encryption_key: Option<HpkePublicKey>,
    ) -> Result<(MlsMessageOut, Option<MlsMessageOut>), SelfUpdateError> {
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
        let create_commit_result = match encryption_key {
            Some(encryption_key) => {
                let group_id = self.group_id().clone();
                let mut own_leaf = self
                    .group
                    .treesync()
                    .own_leaf_node()
                    .ok_or_else(|| {
                        LibraryError::custom("The tree is broken. Couldn't find own leaf.")
                    })?
                    .clone();

                own_leaf.update_and_re_sign(
                    &encryption_key,
                    &credential_bundle,
                    group_id,
                    backend,
                )?;
                let update_proposal = Proposal::Update(UpdateProposal {
                    leaf_node: own_leaf.leaf_node().clone(),
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

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, backend)?;

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
        ))
    }

    /// Creates a proposal to update the own leaf node.
    pub fn propose_self_update(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        key_package: Option<KeyPackage>, // FIXME[FK]: #819 this must be a leaf node.
    ) -> Result<MlsMessageOut, ProposeSelfUpdateError> {
        self.is_operational()?;

        let credential = if let Some(kp) = &key_package {
            // If there's a key pair use the credential in there.
            kp.leaf_node().credential()
        } else {
            // Use the old credential.
            self.credential()?
        };
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &credential
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .ok_or(ProposeSelfUpdateError::NoMatchingCredentialBundle)?;

        let old_credential = self.credential()?;
        let old_credential_bundle: CredentialBundle = backend
            .key_store()
            .read(
                &old_credential
                    .signature_key()
                    .tls_serialize_detached()
                    .map_err(LibraryError::missing_bound_check)?,
            )
            .ok_or(ProposeSelfUpdateError::NoMatchingCredentialBundle)?;

        let tree = self.group.treesync();

        // Here we clone our own leaf to rekey it such that we don't change the
        // tree.
        // The new leaf node will be applied later when the proposal is commited.
        let mut rekeyed_own_leaf = tree
            .own_leaf_node()
            .ok_or_else(|| LibraryError::custom("The tree is broken. Couldn't find own leaf."))?
            .clone();
        if let Some(key_package) = key_package {
            rekeyed_own_leaf.update_and_re_sign(
                key_package.hpke_init_key(),
                &credential_bundle,
                self.group_id().clone(),
                backend,
            )?
        } else {
            rekeyed_own_leaf.rekey(
                self.group_id(),
                self.ciphersuite(),
                ProtocolVersion::default(), // XXX: openmls/openmls#1065
                &credential_bundle,
                backend,
            )?
        };

        let update_proposal = self.group.create_update_proposal(
            self.framing_parameters(),
            &old_credential_bundle,
            rekeyed_own_leaf.leaf_node().clone(),
            backend,
        )?;

        self.own_leaf_nodes.push(rekeyed_own_leaf);
        self.proposal_store
            .add(QueuedProposal::from_authenticated_content(
                self.ciphersuite(),
                backend,
                update_proposal.clone(),
            )?);

        let mls_message = self.content_to_mls_message(update_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }
}
