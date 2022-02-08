#[cfg(any(feature = "test-utils", test))]
use std::collections::BTreeMap;

use core_group::create_commit_params::CreateCommitParams;
use tls_codec::Serialize;

use crate::{ciphersuite::hash_ref::HashReference, ciphersuite::hash_ref::KeyPackageRef};

use super::*;

impl MlsGroup {
    // === Membership management ===

    /// Adds members to the group
    ///
    /// New members are added by providing a `KeyPackage` for each member.
    ///
    /// This operation results in a Commit with a `path`, i.e. it includes an
    /// update of the committer's leaf [KeyPackage].
    ///
    /// If successful, it returns a tuple of [MlsMessageOut] and [Welcome].
    ///
    /// Returns an error if there is a pending commit.
    pub fn add_members(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        key_packages: &[KeyPackage],
    ) -> Result<(MlsMessageOut, Welcome), MlsGroupError> {
        self.is_operational()?;

        if key_packages.is_empty() {
            return Err(MlsGroupError::EmptyInput(EmptyInputError::AddMembers));
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
            .read(&credential.signature_key().tls_serialize_detached()?)
            .ok_or(MlsGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .credential_bundle(&credential_bundle)
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, backend)?;

        let welcome = match create_commit_result.welcome_option {
            Some(welcome) => welcome,
            None => {
                return Err(LibraryError::custom("No secrets to generate commit message.").into())
            }
        };

        // Convert MlsPlaintext messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.plaintext_to_mls_message(create_commit_result.commit, backend)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

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
    ///
    /// Returns an error if there is a pending commit.
    pub fn remove_members(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        members: &[KeyPackageRef],
    ) -> Result<(MlsMessageOut, Option<Welcome>), MlsGroupError> {
        self.is_operational()?;

        if members.is_empty() {
            return Err(MlsGroupError::EmptyInput(EmptyInputError::RemoveMembers));
        }

        // Create inline remove proposals
        let inline_proposals = members
            .iter()
            .map(|member| Proposal::Remove(RemoveProposal { removed: *member }))
            .collect::<Vec<Proposal>>();

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(&credential.signature_key().tls_serialize_detached()?)
            .ok_or(MlsGroupError::NoMatchingCredentialBundle)?;

        // Create Commit over all proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .credential_bundle(&credential_bundle)
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, backend)?;

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

    /// Creates proposals to add members to the group
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_add_member(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,

        key_package: &KeyPackage,
    ) -> Result<MlsMessageOut, MlsGroupError> {
        self.is_operational()?;

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(&credential.signature_key().tls_serialize_detached()?)
            .ok_or(MlsGroupError::NoMatchingCredentialBundle)?;

        let add_proposal = self.group.create_add_proposal(
            self.framing_parameters(),
            &credential_bundle,
            key_package.clone(),
            backend,
        )?;

        self.proposal_store.add(QueuedProposal::from_mls_plaintext(
            self.ciphersuite(),
            backend,
            add_proposal.clone(),
        )?);

        let mls_message = self.plaintext_to_mls_message(add_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }

    /// Creates proposals to remove members from the group
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_remove_member(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        member: &KeyPackageRef,
    ) -> Result<MlsMessageOut, MlsGroupError> {
        self.is_operational()?;

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(&credential.signature_key().tls_serialize_detached()?)
            .ok_or(MlsGroupError::NoMatchingCredentialBundle)?;

        let remove_proposal = self.group.create_remove_proposal(
            self.framing_parameters(),
            &credential_bundle,
            member,
            backend,
        )?;

        self.proposal_store.add(QueuedProposal::from_mls_plaintext(
            self.ciphersuite(),
            backend,
            remove_proposal.clone(),
        )?);

        let mls_message = self.plaintext_to_mls_message(remove_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }

    /// Leave the group
    ///
    /// Returns an error if there is a pending commit.
    pub fn leave_group(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Result<MlsMessageOut, MlsGroupError> {
        self.is_operational()?;

        let credential = self.credential()?;
        let credential_bundle: CredentialBundle = backend
            .key_store()
            .read(&credential.signature_key().tls_serialize_detached()?)
            .ok_or(MlsGroupError::NoMatchingCredentialBundle)?;

        let removed = self
            .group
            .key_package_ref()
            .ok_or_else(|| LibraryError::custom("No key package reference for own key package."))?;
        let remove_proposal = self.group.create_remove_proposal(
            self.framing_parameters(),
            &credential_bundle,
            removed,
            backend,
        )?;

        self.proposal_store.add(QueuedProposal::from_mls_plaintext(
            self.ciphersuite(),
            backend,
            remove_proposal.clone(),
        )?);

        self.plaintext_to_mls_message(remove_proposal, backend)
    }

    /// Gets a list of [`KeyPackage`]s of the current group members.
    pub fn members(&self) -> Result<Vec<&KeyPackage>, MlsGroupError> {
        Ok(self
            .group
            .treesync()
            .full_leaves()?
            .iter()
            .map(|(_, &kp)| kp)
            .collect())
    }

    /// Gets the current list of members, indexed with the leaf index.
    /// This should go away in future when all tests are rewritten to use key
    /// package references instead of leaf indices.
    #[cfg(any(feature = "test-utils", test))]
    pub fn indexed_members(&self) -> Result<BTreeMap<u32, &KeyPackage>, MlsGroupError> {
        Ok(self.group.treesync().full_leaves()?)
    }
}

/// Helper `enum` that classifies the kind of remove operation. This can be used to
/// better interpret the semantic value of a remove proposal that is covered in a
/// Commit message.
#[derive(Debug)]
pub enum RemoveOperation {
    /// We issued a remove proposal for ourselves in the previous epoch and
    /// the proposal has now been committed.
    WeLeft,
    /// Someone else (indicated by the [`Sender`]) removed us from the group.
    WeWereRemovedBy(SenderNew),
    /// Another member (indicated by the [`HashReference`]) requested to leave
    /// the group by issuing a remove proposal in the previous epoch and the
    /// proposal has now been committed.
    TheyLeft(HashReference),
    /// Another member (indicated by the [`HashRefrence`]) was removed by the [`Sender`].
    TheyWereRemovedBy((HashReference, SenderNew)),
    /// We removed another member (indicated by the [`HashReference`]).
    WeRemovedThem(HashReference),
}

impl RemoveOperation {
    /// Construct a new [`RemoveOperation`] from a [`QueuedRemoveProposal`] and the
    /// corresponding [`MlsGroup`].
    pub fn new(
        queued_remove_proposal: QueuedRemoveProposal,
        group: &MlsGroup,
    ) -> Result<Self, LibraryError> {
        let own_hash_ref = match group.key_package_ref() {
            Some(key_package_ref) => key_package_ref,
            None => {
                return Err(LibraryError::custom(
                    "RemoveOperation::new(): Own KeyPackage was empty.",
                ))
            }
        };
        let sender = queued_remove_proposal.sender();
        let removed = queued_remove_proposal.remove_proposal().removed();

        // We start with the cases where the sender is a group member
        if let SenderNew::Member(hash_ref) = sender {
            // We authored the remove proposal
            if hash_ref == own_hash_ref {
                if removed == own_hash_ref {
                    // We left
                    return Ok(Self::WeLeft);
                } else {
                    // We removed another member
                    return Ok(Self::WeRemovedThem(*removed));
                }
            }

            // Another member left
            if removed == hash_ref {
                return Ok(Self::TheyLeft(*removed));
            }
        }

        // The sender is not necessarily a group member. This covers all sender
        // types (members, pre-configured senders and new members).

        if removed == own_hash_ref {
            // We were removed
            Ok(Self::WeWereRemovedBy(sender.clone()))
        } else {
            // Another member was removed
            Ok(Self::TheyWereRemovedBy((*removed, sender.clone())))
        }
    }
}
