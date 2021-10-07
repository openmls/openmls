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
                (self.group.decrypt(&ciphertext)?, Some(aad))
            }
            // If it is a plaintext message we have to verify it first
            MlsMessageIn::Plaintext(unverified_plaintext) => {
                // Get the proper context to verify the signature on the plaintext
                let context = self
                    .group
                    .context()
                    .tls_serialize_detached()
                    .map_err(MlsGroupError::CodecError)?;
                let members = self.indexed_members();
                let credential = members
                    .get(&unverified_plaintext.sender_index())
                    .ok_or(InvalidMessageError::UnknownSender)?;
                // Verify the signature
                let plaintext: MlsPlaintext = unverified_plaintext
                    .set_context(&context)
                    .verify(credential)?;
                // Verify membership tag
                // TODO #106: Support external senders
                if plaintext.is_proposal()
                    && plaintext.sender().is_member()
                    && self.group.verify_membership_tag(&plaintext).is_err()
                {
                    return Err(ManagedGroupError::InvalidMessage(
                        InvalidMessageError::MembershipTagMismatch,
                    ));
                }
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
                    self.pending_proposals.push(plaintext);
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
                // If all proposals were valid, we continue with applying the Commit
                // message
                let proposals = &self
                    .pending_proposals
                    .iter()
                    .collect::<Vec<&MlsPlaintext>>();
                // TODO #141
                match self
                    .group
                    .apply_commit(&plaintext, proposals, &self.own_kpbs, None)
                {
                    Ok(()) => {
                        // Since the Commit was applied without errors, we can collect
                        // all proposals from the Commit and generate events
                        events.append(&mut self.prepare_events(
                            self.ciphersuite(),
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
                    Err(apply_commit_error) => match apply_commit_error {
                        MlsGroupError::ApplyCommitError(ApplyCommitError::SelfRemoved) => {
                            // Prepare events
                            events.append(&mut self.prepare_events(
                                self.ciphersuite(),
                                commit.proposals.as_slice(),
                                plaintext.sender_index(),
                                &indexed_members,
                            ));
                            // The group is no longer active
                            self.active = false;
                        }
                        MlsGroupError::ApplyCommitError(e) => {
                            return Err(ManagedGroupError::InvalidMessage(
                                InvalidMessageError::CommitError(e),
                            ))
                        }
                        _ => {
                            let error_string =
                                "apply_commit() did not return an ApplyCommitError.".to_string();
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
}
