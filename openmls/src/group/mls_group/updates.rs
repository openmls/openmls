use core_group::create_commit_params::CreateCommitParams;
use tls_codec::Serialize;

use crate::{treesync::LeafNode, versions::ProtocolVersion};

use super::*;

impl MlsGroup {
    /// Updates the own leaf node.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] (containing the
    /// commit) and an optional [`MlsMessageOut`] (containing the [`Welcome`]).
    /// The [Welcome] is [Some] when the queue of pending proposals contained
    /// add proposals
    ///
    /// Returns an error if there is a pending commit.
    ///
    /// TODO #1208 : The caller should be able to optionally provide a
    /// [`LeafNode`] here, so that things like extensions can be changed via
    /// commit.
    pub fn self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    ) -> Result<(MlsMessageOut, Option<MlsMessageOut>), SelfUpdateError<KeyStore::Error>> {
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

        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .credential_bundle(&credential_bundle)
            .proposal_store(&self.proposal_store)
            .build();
        // Create Commit over all proposals. If a `KeyPackageBundle` was passed
        // in, use it to create an update proposal by value. TODO #751
        let create_commit_result = self.group.create_commit(params, backend)?;

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
    pub fn propose_self_update<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        leaf_node: Option<LeafNode>,
    ) -> Result<MlsMessageOut, ProposeSelfUpdateError<KeyStore::Error>> {
        self.is_operational()?;

        let credential = if let Some(leaf) = &leaf_node {
            // If there's a key pair use the credential in there.
            leaf.credential()
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
        // The new leaf node will be applied later when the proposal is
        // committed.
        let mut own_leaf = tree
            .leaf(self.own_leaf_index())
            .ok_or_else(|| LibraryError::custom("The tree is broken. Couldn't find own leaf."))?
            .clone();
        if let Some(leaf) = leaf_node {
            own_leaf.update_and_re_sign(
                leaf.encryption_key(),
                &credential_bundle,
                self.group_id().clone(),
                backend,
            )?
        } else {
            let keypair = own_leaf.rekey(
                self.group_id(),
                self.ciphersuite(),
                ProtocolVersion::default(), // XXX: openmls/openmls#1065
                &credential_bundle,
                backend,
            )?;
            // TODO #1207: Move to the top of the function.
            keypair
                .write_to_key_store(backend)
                .map_err(ProposeSelfUpdateError::KeyStoreError)?;
        };

        let update_proposal = self.group.create_update_proposal(
            self.framing_parameters(),
            &old_credential_bundle,
            own_leaf.leaf_node().clone(),
            backend,
        )?;

        self.own_leaf_nodes.push(own_leaf);
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
