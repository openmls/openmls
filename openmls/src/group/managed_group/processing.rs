use mls_group::proposals::StagedProposal;

use crate::prelude::ErrorString;

use super::*;

impl ManagedGroup {
    // === Process messages ===

    /// Processes any incoming messages from the DS (MlsPlaintext &
    /// MlsCiphertext) and triggers the corresponding callback functions.
    /// Return a list of `GroupEvent` that contain the individual events that
    /// occurred while processing messages.
    pub fn process_message(
        &mut self,
        message: MlsMessageIn,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<Vec<GroupEvent>, ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        let mut events = Vec::new();
        // Check the type of message we received
        let (plaintext, aad_option) = match message {
            // If it is a ciphertext we decrypt it and return the plaintext message
            MlsMessageIn::Ciphertext(ciphertext) => {
                let aad = ciphertext.authenticated_data.clone();
                let unverified_plaintext = self.group.decrypt(&ciphertext, backend)?;
                let plaintext = self.group.verify(unverified_plaintext, backend)?;
                (plaintext, Some(aad))
            }
            // If it is a plaintext message we have to verify it first
            MlsMessageIn::Plaintext(mut verifiable_plaintext) => {
                // Verify membership tag
                // TODO #106: Support external senders
                if verifiable_plaintext.is_proposal()
                    && verifiable_plaintext.sender().is_member()
                    && self
                        .group
                        // This sets the context implicitly.
                        .verify_membership_tag(backend, &mut verifiable_plaintext)
                        .is_err()
                {
                    return Err(ManagedGroupError::InvalidMessage(
                        InvalidMessageError::MembershipTagMismatch,
                    ));
                }
                // Verify the signature
                let plaintext: MlsPlaintext = self.group.verify(verifiable_plaintext, backend)?;
                (plaintext, None)
            }
        };
        // Save the current member list for validation end events
        let indexed_members = self.indexed_members();
        // See what kind of message it is
        match plaintext.content() {
            MlsPlaintextContentType::Proposal(ref proposal) => {
                // Incoming proposals are validated against the application validation
                // policy and then appended to the internal `pending_proposal` list.
                // TODO #133: Semantic validation of proposals
                if self.validate_proposal(proposal, plaintext.sender_index(), &indexed_members) {
                    self.pending_proposals.push(plaintext.clone());
                    let staged_proposal =
                        StagedProposal::from_mls_plaintext(self.ciphersuite(), backend, plaintext)
                            .map_err(|_| InvalidMessageError::InvalidProposal)?;
                    self.proposal_store.add(staged_proposal);
                } else {
                    // The proposal was invalid
                    return Err(ManagedGroupError::InvalidMessage(
                        InvalidMessageError::InvalidProposal,
                    ));
                }
            }
            MlsPlaintextContentType::Commit(ref commit) => {
                // Validate inline proposals
                if !self.validate_inline_proposals(
                    commit.proposals.as_slice(),
                    plaintext.sender_index(),
                    &indexed_members,
                ) {
                    return Err(ManagedGroupError::InvalidMessage(
                        InvalidMessageError::CommitWithInvalidProposals,
                    ));
                }
                // If all proposals were valid, we continue with staging the Commit
                // message
                // TODO #141
                match self.group.stage_commit(
                    &plaintext,
                    &self.proposal_store,
                    &self.own_kpbs,
                    None,
                    backend,
                ) {
                    Ok(staged_commit) => {
                        // Since the Commit was applied without errors, we can merge it and collect
                        // all proposals from the Commit and generate events
                        self.group.merge_commit(staged_commit);
                        events.append(&mut self.prepare_events(
                            self.ciphersuite(),
                            backend,
                            commit.proposals.as_slice(),
                            plaintext.sender_index(),
                            &indexed_members,
                        ));

                        // If a Commit has an update path, it is additionally to be treated
                        // like a commited UpdateProposal.
                        if commit.has_path() {
                            events.push(GroupEvent::MemberUpdated(MemberUpdatedEvent::new(
                                aad_option.unwrap_or_default().into(),
                                indexed_members[&plaintext.sender_index()].clone(),
                            )));
                        }

                        // Extract and store the resumption secret for the current epoch
                        let resumption_secret = self.group.epoch_secrets().resumption_secret();
                        self.resumption_secret_store
                            .add(self.group.context().epoch(), resumption_secret.clone());
                        // We don't need the pending proposals and key package bundles any
                        // longer
                        self.pending_proposals.clear();
                        self.own_kpbs.clear();
                    }
                    Err(stage_commit_error) => match stage_commit_error {
                        MlsGroupError::StageCommitError(StageCommitError::SelfRemoved) => {
                            // Prepare events
                            events.append(&mut self.prepare_events(
                                self.ciphersuite(),
                                backend,
                                commit.proposals.as_slice(),
                                plaintext.sender_index(),
                                &indexed_members,
                            ));
                            // The group is no longer active
                            self.active = false;
                        }
                        MlsGroupError::StageCommitError(e) => {
                            return Err(ManagedGroupError::InvalidMessage(
                                InvalidMessageError::CommitError(e),
                            ))
                        }
                        _ => {
                            let error_string =
                                "stage_commit() did not return an StageCommitError.".to_string();
                            events.push(GroupEvent::Error(ErrorEvent::new(
                                ManagedGroupError::LibraryError(ErrorString::from(error_string)),
                            )));
                        }
                    },
                }
            }
            MlsPlaintextContentType::Application(ref app_message) => {
                // Save the application message as an event
                events.push(GroupEvent::ApplicationMessage(
                    ApplicationMessageEvent::new(
                        aad_option
                            .ok_or(ManagedGroupError::InvalidMessage(
                                InvalidMessageError::InvalidApplicationMessage,
                            ))?
                            .into(),
                        indexed_members[&plaintext.sender_index()].clone(),
                        app_message.as_slice().to_vec(),
                    ),
                ));
            }
        }

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok(events)
    }

    /// Process pending proposals
    pub fn process_pending_proposals(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<(MlsMessageOut, Option<Welcome>), ManagedGroupError> {
        if !self.active {
            return Err(ManagedGroupError::UseAfterEviction(UseAfterEviction::Error));
        }
        // Include pending proposals into Commit
        let messages_to_commit: Vec<&MlsPlaintext> = self.pending_proposals.iter().collect();

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(credential.signature_key())
            .ok_or(ManagedGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all pending proposals
        // TODO #141
        let (commit, welcome_option, kpb_option) = self.group.create_commit(
            self.framing_parameters(),
            &credential_bundle,
            Proposals {
                proposals_by_reference: &messages_to_commit,
                proposals_by_value: &[],
            },
            true,
            None,
            backend,
        )?;

        // If it was a full Commit, we have to save the KeyPackageBundle for later
        if let Some(kpb) = kpb_option {
            self.own_kpbs.push(kpb);
        }

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.plaintext_to_mls_message(commit, backend)?;

        // Since the state of the group was changed, call the auto-save function
        self.auto_save();

        Ok((mls_message, welcome_option))
    }
}
