//! MLS group membership
//!
//! This module contains membership-related operations and exposes [`RemoveOperation`].

use openmls_traits::signatures::Signer;
use public_group::create_commit_params::CreateCommitParams;

use crate::{
    binary_tree::array_representation::LeafNodeIndex, group::errors::CreateAddProposalError,
    messages::group_info::GroupInfo, treesync::LeafNode,
};

use super::{
    errors::{AddMembersError, LeaveGroupError, RemoveMembersError},
    *,
};

impl MlsGroup {
    /// Adds members to the group.
    ///
    /// New members are added by providing a `KeyPackage` for each member.
    ///
    /// This operation results in a Commit with a `path`, i.e. it includes an
    /// update of the committer's leaf [KeyPackage].
    ///
    /// If successful, it returns a triple of [`MlsMessageOut`]s, where the first
    /// contains the commit, the second one the [Welcome] and the third an optional [GroupInfo] that
    /// will be [Some] if the group has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn add_members<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        key_packages: &[KeyPackage],
    ) -> Result<(MlsMessageOut, MlsMessageOut, Option<GroupInfo>), AddMembersError<KeyStore::Error>>
    {
        self.is_operational()?;

        if key_packages.is_empty() {
            return Err(AddMembersError::EmptyInput(EmptyInputError::AddMembers));
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

        // Create Commit over all proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, backend, signer)?;

        let welcome = match create_commit_result.welcome_option {
            Some(welcome) => welcome,
            None => {
                return Err(LibraryError::custom("No secrets to generate commit message.").into())
            }
        };

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

        Ok((
            mls_messages,
            MlsMessageOut::from_welcome(welcome, self.group.version()),
            create_commit_result.group_info,
        ))
    }

    /// Returns a reference to the own [`LeafNode`].
    pub fn own_leaf(&self) -> Option<&LeafNode> {
        self.group
            .treesync()
            .leaf(self.group.own_leaf_index())
            .map(|l| l.leaf_node())
    }

    /// Removes members from the group.
    ///
    /// Members are removed by providing the member's leaf index.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] (containing the
    /// commit), an optional [`MlsMessageOut`] (containing the [`Welcome`]) and the current
    /// [GroupInfo].
    /// The [Welcome] is [Some] when the queue of pending proposals contained
    /// add proposals
    /// The [GroupInfo] is [Some] if the group has the `use_ratchet_tree_extension` flag set.

    ///
    /// Returns an error if there is a pending commit.
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn remove_members<KeyStore: OpenMlsKeyStore>(
        &mut self,
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        members: &[LeafNodeIndex],
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        RemoveMembersError<KeyStore::Error>,
    > {
        self.is_operational()?;

        if members.is_empty() {
            return Err(RemoveMembersError::EmptyInput(
                EmptyInputError::RemoveMembers,
            ));
        }

        // Create inline remove proposals
        let mut inline_proposals = Vec::new();
        for member in members.iter() {
            inline_proposals.push(Proposal::Remove(RemoveProposal { removed: *member }))
        }

        // Create Commit over all proposals
        // TODO #751
        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, backend, signer)?;

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
            create_commit_result.group_info,
        ))
    }

    /// Creates proposals to add members to the group.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_add_member(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        key_package: &KeyPackage,
    ) -> Result<MlsMessageOut, ProposeAddMemberError> {
        self.is_operational()?;

        let add_proposal = self
            .group
            .create_add_proposal(self.framing_parameters(), key_package.clone(), signer)
            .map_err(|e| match e {
                CreateAddProposalError::LibraryError(e) => e.into(),
                CreateAddProposalError::LeafNodeValidation(error) => {
                    ProposeAddMemberError::LeafNodeValidation(error)
                }
            })?;

        self.proposal_store
            .add(QueuedProposal::from_authenticated_content(
                self.ciphersuite(),
                backend,
                add_proposal.clone(),
            )?);

        let mls_message = self.content_to_mls_message(add_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }

    /// Creates proposals to remove members from the group.
    /// The `member` has to be the member's leaf index.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_remove_member(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
        member: LeafNodeIndex,
    ) -> Result<MlsMessageOut, ProposeRemoveMemberError> {
        self.is_operational()?;

        let remove_proposal = self
            .group
            .create_remove_proposal(self.framing_parameters(), member, signer)
            .map_err(|_| ProposeRemoveMemberError::UnknownMember)?;

        self.proposal_store
            .add(QueuedProposal::from_authenticated_content(
                self.ciphersuite(),
                backend,
                remove_proposal.clone(),
            )?);

        let mls_message = self.content_to_mls_message(remove_proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok(mls_message)
    }

    /// Leave the group.
    ///
    /// Creates a Remove Proposal that needs to be covered by a Commit from a different member.
    /// The Remove Proposal is returned as a [`MlsMessageOut`].
    ///
    /// Returns an error if there is a pending commit.
    pub fn leave_group(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        signer: &impl Signer,
    ) -> Result<MlsMessageOut, LeaveGroupError> {
        self.is_operational()?;

        let removed = self.group.own_leaf_index();
        let remove_proposal = self
            .group
            .create_remove_proposal(self.framing_parameters(), removed, signer)
            .map_err(|_| LibraryError::custom("Creating a self removal should not fail"))?;

        self.proposal_store
            .add(QueuedProposal::from_authenticated_content(
                self.ciphersuite(),
                backend,
                remove_proposal.clone(),
            )?);

        Ok(self.content_to_mls_message(remove_proposal, backend)?)
    }

    /// Returns a list of [`Member`]s in the group.
    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.group.treesync().full_leave_members()
    }

    /// Returns the [`Credential`] of a member corresponding to the given
    /// leaf index. Returns `None` if the member can not be found in this group.
    pub fn member(&self, leaf_index: LeafNodeIndex) -> Option<&Credential> {
        self.group
            .treesync()
            // This will return an error if the member can't be found.
            .leaf(leaf_index)
            .map(|leaf| leaf.credential())
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
    WeWereRemovedBy(Sender),
    /// Another member (indicated by the leaf index) requested to leave
    /// the group by issuing a remove proposal in the previous epoch and the
    /// proposal has now been committed.
    TheyLeft(LeafNodeIndex),
    /// Another member (indicated by the leaf index) was removed by the [`Sender`].
    TheyWereRemovedBy((LeafNodeIndex, Sender)),
    /// We removed another member (indicated by the leaf index).
    WeRemovedThem(LeafNodeIndex),
}

impl RemoveOperation {
    /// Constructs a new [`RemoveOperation`] from a [`QueuedRemoveProposal`] and the
    /// corresponding [`MlsGroup`].
    pub fn new(
        queued_remove_proposal: QueuedRemoveProposal,
        group: &MlsGroup,
    ) -> Result<Self, LibraryError> {
        let own_index = group.own_leaf_index();
        let sender = queued_remove_proposal.sender();
        let removed = queued_remove_proposal.remove_proposal().removed();

        // We start with the cases where the sender is a group member
        if let Sender::Member(leaf_index) = sender {
            // We authored the remove proposal
            if *leaf_index == own_index {
                if removed == own_index {
                    // We left
                    return Ok(Self::WeLeft);
                } else {
                    // We removed another member
                    return Ok(Self::WeRemovedThem(removed));
                }
            }

            // Another member left
            if removed == *leaf_index {
                return Ok(Self::TheyLeft(removed));
            }
        }

        // The sender is not necessarily a group member. This covers all sender
        // types (members, pre-configured senders and new members).

        if removed == own_index {
            // We were removed
            Ok(Self::WeWereRemovedBy(sender.clone()))
        } else {
            // Another member was removed
            Ok(Self::TheyWereRemovedBy((removed, sender.clone())))
        }
    }
}
