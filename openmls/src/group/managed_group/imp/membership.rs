use super::*;

impl ManagedGroup {
    // === Membership management ===

    /// Adds members to the group
    ///
    /// New members are added by providing a `KeyPackage` for each member.
    ///
    /// This operation results in a Commit with a `path`, i.e. it includes an
    /// update of the committer's leaf `KeyPackage`.
    ///
    /// If successful, it returns a `Vec` of
    /// [`MlsMessage`] and a [`Welcome`] message.
    pub fn add_members(
        &mut self,
        key_store: &KeyStore,
        key_packages: &[KeyPackage],
    ) -> Result<(MlsMessageOut, Welcome), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        if key_packages.is_empty() {
            return Err(ManagedGroupError::EmptyInput(EmptyInputError::AddMembers));
        }

        // Create add proposals by value from key packages
        let proposals = key_packages
            .iter()
            .map(|key_package| {
                Proposal::Add(AddProposal {
                    key_package: key_package.clone(),
                })
            })
            .collect::<Vec<Proposal>>();
        let proposals_by_value = &proposals.iter().collect::<Vec<&Proposal>>();

        // Include pending proposals
        let proposals_by_reference = &self
            .pending_proposals
            .iter()
            .collect::<Vec<&MlsPlaintext>>();

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #141
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &credential_bundle,
            proposals_by_reference,
            proposals_by_value,
            true,
            None,
        )?;
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
        let mls_messages = self.plaintext_to_mls_message(commit)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_messages, welcome))
    }

    /// Removes members from the group
    ///
    /// Members are removed by providing the index of their leaf in the tree.
    ///
    /// If successful, it returns a `Vec` of
    /// [`MlsMessage`] and an optional [`Welcome`] message if there were add
    /// proposals in the queue of pending proposals.
    pub fn remove_members(
        &mut self,
        key_store: &KeyStore,
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

        // Create add proposals by value
        let proposals = members
            .iter()
            .map(|member| {
                Proposal::Remove(RemoveProposal {
                    removed: *member as u32,
                })
            })
            .collect::<Vec<Proposal>>();
        let proposals_by_value = &proposals.iter().collect::<Vec<&Proposal>>();

        // Include pending proposals
        let proposals_by_reference = &self
            .pending_proposals
            .iter()
            .collect::<Vec<&MlsPlaintext>>();

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #141
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            &self.aad,
            &credential_bundle,
            proposals_by_reference,
            proposals_by_value,
            false,
            None,
        )?;

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
        let mls_message = self.plaintext_to_mls_message(commit)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_message, welcome_option))
    }

    /// Creates proposals to add members to the group
    pub fn propose_add_member(
        &mut self,
        key_store: &KeyStore,
        key_package: &KeyPackage,
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let add_proposal =
            self.group
                .create_add_proposal(&self.aad, &credential_bundle, key_package.clone())?;

        let mls_message = self.plaintext_to_mls_message(add_proposal)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(mls_message)
    }

    /// Creates proposals to remove members from the group
    pub fn propose_remove_member(
        &mut self,
        key_store: &KeyStore,
        member: usize,
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let remove_proposal = self.group.create_remove_proposal(
            &self.aad,
            &credential_bundle,
            LeafIndex::from(member),
        )?;

        let mls_message = self.plaintext_to_mls_message(remove_proposal)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(mls_message)
    }

    /// Leave the group
    pub fn leave_group(
        &mut self,
        key_store: &KeyStore,
    ) -> Result<MlsMessageOut, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }

        let credential = self.credential()?;
        let credential_bundle = key_store
            .get_credential_bundle(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        let remove_proposal = self.group.create_remove_proposal(
            &self.aad,
            &credential_bundle,
            self.group.tree().own_node_index(),
        )?;

        self.plaintext_to_mls_message(remove_proposal)
    }

    /// Gets the current list of members
    pub fn members(&self) -> Vec<Credential> {
        let mut members: Vec<Credential> = vec![];
        let tree = self.group.tree();
        let leaf_count = self.group.tree().leaf_count();
        for index in 0..leaf_count.as_usize() {
            let leaf = &tree.nodes[LeafIndex::from(index)];
            if let Some(leaf_node) = leaf.key_package() {
                members.push(leaf_node.credential().clone());
            }
        }
        members
    }
}
