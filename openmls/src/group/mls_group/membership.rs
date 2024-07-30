//! MLS group membership
//!
//! This module contains membership-related operations and exposes [`RemoveOperation`].

use core_group::create_commit_params::CreateCommitParams;
use openmls_traits::{signatures::Signer, storage::StorageProvider as _};

use super::{
    errors::{AddMembersError, LeaveGroupError, RemoveMembersError},
    *,
};
use crate::{
    binary_tree::array_representation::LeafNodeIndex, messages::group_info::GroupInfo,
    storage::OpenMlsProvider, treesync::LeafNode,
};

impl MlsGroup {
    /// Adds members to the group.
    ///
    /// New members are added by providing a `KeyPackage` for each member.
    ///
    /// This operation results in a Commit with a `path`, i.e. it includes an
    /// update of the committer's leaf [KeyPackage]. To add members without
    /// forcing an update of the committer's leaf [KeyPackage], use
    /// [`Self::add_members_without_update()`].
    ///
    /// If successful, it returns a triple of [`MlsMessageOut`]s, where the first
    /// contains the commit, the second one the [`Welcome`] and the third an optional [GroupInfo] that
    /// will be [Some] if the group has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn add_members<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        key_packages: &[KeyPackage],
    ) -> Result<
        (MlsMessageOut, MlsMessageOut, Option<GroupInfo>),
        AddMembersError<Provider::StorageError>,
    > {
        self.add_members_internal(provider, signer, key_packages, true)
    }

    /// Adds members to the group.
    ///
    /// New members are added by providing a `KeyPackage` for each member.
    ///
    /// This operation results in a Commit that does not necessarily include a
    /// `path`, i.e. an update of the committer's leaf [KeyPackage]. In
    /// particular, it will only include a path if the group's proposal store
    /// includes one or more proposals that require a path (see [Section 17.4 of
    /// RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.4) for
    /// a list of proposals and whether they require a path).
    ///
    /// If successful, it returns a triple of [`MlsMessageOut`]s, where the
    /// first contains the commit, the second one the [`Welcome`] and the third
    /// an optional [GroupInfo] that will be [Some] if the group has the
    /// `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn add_members_without_update<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        key_packages: &[KeyPackage],
    ) -> Result<
        (MlsMessageOut, MlsMessageOut, Option<GroupInfo>),
        AddMembersError<Provider::StorageError>,
    > {
        self.add_members_internal(provider, signer, key_packages, false)
    }

    #[allow(clippy::type_complexity)]
    fn add_members_internal<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        key_packages: &[KeyPackage],
        force_self_update: bool,
    ) -> Result<
        (MlsMessageOut, MlsMessageOut, Option<GroupInfo>),
        AddMembersError<Provider::StorageError>,
    > {
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
            .inline_proposals(inline_proposals)
            .force_self_update(force_self_update)
            .build();
        let create_commit_result = self.group.create_commit(params, provider, signer)?;

        let welcome = match create_commit_result.welcome_option {
            Some(welcome) => welcome,
            None => {
                return Err(LibraryError::custom("No secrets to generate commit message.").into())
            }
        };

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_messages = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(AddMembersError::StorageError)?;

        self.reset_aad();
        Ok((
            mls_messages,
            MlsMessageOut::from_welcome(welcome, self.group.version()),
            create_commit_result.group_info,
        ))
    }

    /// Returns a reference to the own [`LeafNode`].
    pub fn own_leaf(&self) -> Option<&LeafNode> {
        self.group.public_group().leaf(self.group.own_leaf_index())
    }

    /// Removes members from the group.
    ///
    /// Members are removed by providing the member's leaf index.
    ///
    /// If successful, it returns a tuple of [`MlsMessageOut`] (containing the
    /// commit), an optional [`MlsMessageOut`] (containing the [`Welcome`]) and the current
    /// [GroupInfo].
    /// The [`Welcome`] is [Some] when the queue of pending proposals contained
    /// add proposals
    /// The [GroupInfo] is [Some] if the group has the `use_ratchet_tree_extension` flag set.
    ///
    /// Returns an error if there is a pending commit.
    ///
    /// [`Welcome`]: crate::messages::Welcome
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn remove_members<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        members: &[LeafNodeIndex],
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        RemoveMembersError<Provider::StorageError>,
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
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, provider, signer)?;

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by
        // the configuration
        let mls_message = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(RemoveMembersError::StorageError)?;

        self.reset_aad();
        Ok((
            mls_message,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.group.version())),
            create_commit_result.group_info,
        ))
    }

    /// Leave the group.
    ///
    /// Creates a Remove Proposal that needs to be covered by a Commit from a different member.
    /// The Remove Proposal is returned as a [`MlsMessageOut`].
    ///
    /// Returns an error if there is a pending commit.
    pub fn leave_group<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<MlsMessageOut, LeaveGroupError<Provider::StorageError>> {
        self.is_operational()?;

        let removed = self.group.own_leaf_index();
        let remove_proposal = self
            .group
            .create_remove_proposal(self.framing_parameters(), removed, signer)
            .map_err(|_| LibraryError::custom("Creating a self removal should not fail"))?;

        let ciphersuite = self.ciphersuite();

        self.proposal_store_mut()
            .add(QueuedProposal::from_authenticated_content_by_ref(
                ciphersuite,
                provider.crypto(),
                remove_proposal.clone(),
            )?);

        self.reset_aad();
        Ok(self.content_to_mls_message(remove_proposal, provider)?)
    }

    /// Returns a list of [`Member`]s in the group.
    pub fn members(&self) -> impl Iterator<Item = Member> + '_ {
        self.group.public_group().members()
    }

    /// Returns the [`Credential`] of a member corresponding to the given
    /// leaf index. Returns `None` if the member can not be found in this group.
    pub fn member(&self, leaf_index: LeafNodeIndex) -> Option<&Credential> {
        self.group
            .public_group()
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
