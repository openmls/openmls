use mls_group::create_commit_params::CreateCommitParams;

use super::*;

impl ManagedGroup {
    // === Membership management ===

    /// Adds members to the group
    ///
    /// New members are added by providing a `KeyPackage` for each member.
    ///
    /// This operation results in a Commit with a `path`, i.e. it includes an
    /// update of the committer's leaf [KeyPackage].
    ///
    /// If successful, it returns a tuple of [MlsMessageOut] and [Welcome].
    pub fn add_members(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        key_packages: &[KeyPackage],
    ) -> Result<(MlsMessageOut, Welcome), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        if key_packages.is_empty() {
            return Err(ManagedGroupError::EmptyInput(EmptyInputError::AddMembers));
        }

        // Create inline add proposals from key packages
        let inline_proposals = key_packages
            .iter()
            .map(|key_package| {
                Proposal::Add(AddProposal {
                    key_package: key_package.clone(),
                })
            })
            .collect::<Vec<Proposal>>();

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #141
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .credential_bundle(&credential_bundle)
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let (commit, welcome_option, kpb_option) = self.group.create_commit(params, backend)?;
        log::error!("plaintext (foo): {:?}", commit);

        let welcome = match welcome_option {
            Some(welcome) => welcome,
            None => {
                return Err(ManagedGroupError::LibraryError(
                    "No secrets to generate commit message.".into(),
                ))
            }
        };

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_message(commit, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_messages, welcome))
    }

    /// Removes members from the group
    ///
    /// Members are removed by providing the index of their leaf in the tree.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] and an optional [`Welcome`].
    /// The [Welcome] is [Some] when the queue of pending proposals contained add proposals
    pub fn remove_members(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        members: &[usize],
    ) -> Result<(MlsMessageOut, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        if members.is_empty() {
            return Err(ManagedGroupError::EmptyInput(
                EmptyInputError::RemoveMembers,
            ));
        }

        // Create inline remove proposals
        let inline_proposals = members
            .iter()
            .map(|member| {
                Proposal::Remove(RemoveProposal {
                    removed: *member as u32,
                })
            })
            .collect::<Vec<Proposal>>();

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #141
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .credential_bundle(&credential_bundle)
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let (commit, welcome_option, kpb_option) = self.group.create_commit(params, backend)?;

        // It has to be a full Commit and we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        } else {
            return Err(ManagedGroupError::LibraryError(
                "We didn't get a key package for a full commit.".into(),
            ));
        }

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.plaintext_to_mls_message(commit, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, welcome_option))
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_member(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,

        key_package: &KeyPackage,
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let add_proposal = self.group.create_add_proposal(
            self.framing_parameters(),
            &credential_bundle,
            key_package.clone(),
            backend,
        )?;

        let mls_message = self.plaintext_to_mls_message(add_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }

    /// Creates proposals to remove members from the group
    pub fn propose_remove_member(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        member: LeafIndex,
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let remove_proposal = self.group.create_remove_proposal(
            self.framing_parameters(),
            &credential_bundle,
            member,
            backend,
        )?;

        let mls_message = self.plaintext_to_mls_message(remove_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }

    /// Leave the group
    pub fn leave_group(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let remove_proposal = self.group.create_remove_proposal(
            self.framing_parameters(),
            &credential_bundle,
            self.group.tree().own_leaf_index(),
            backend,
        )?;

        self.plaintext_to_mls_message(remove_proposal, backend)
    }

    /// Gets the current list of members
    pub fn members(&self) -> Result<Vec<&Credential>, ManagedGroupError> {
        Ok(self
            .group
            .tree()
            .full_leaves()?
            .iter()
            .map(|(_, kp)| kp.credential())
            .collect())
    }
}
