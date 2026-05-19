//! This module describes the public storage provider and type traits.
//! Applications that only want to use the `PublicGroup` only need to implement
//! the `PublicStorageProvider` trait, and not the `StorageProvider` trait.

use crate::storage::StorageProvider;

#[maybe_async::maybe_async(AFIT)]
#[allow(async_fn_in_trait)]
pub trait PublicStorageProvider<const VERSION: u16> {
    /// An opaque error returned by all methods on this trait.
    type PublicError: core::fmt::Debug + std::error::Error;

    /// Get the version of this provider.
    fn version() -> u16 {
        VERSION
    }

    /// Write the TreeSync tree.
    async fn write_tree<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        TreeSync: crate::storage::traits::TreeSync<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::PublicError>;

    /// Write the interim transcript hash.
    async fn write_interim_transcript_hash<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        InterimTranscriptHash: crate::storage::traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::PublicError>;

    /// Write the group context.
    async fn write_context<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        GroupContext: crate::storage::traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::PublicError>;

    /// Write the confirmation tag.
    async fn write_confirmation_tag<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ConfirmationTag: crate::storage::traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::PublicError>;

    /// Enqueue a proposal.
    async fn queue_proposal<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ProposalRef: crate::storage::traits::ProposalRef<VERSION>,
        QueuedProposal: crate::storage::traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::PublicError>;

    /// Returns all queued proposals for the group with group id `group_id`, or an empty vector of none are stored.
    async fn queued_proposals<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ProposalRef: crate::storage::traits::ProposalRef<VERSION>,
        QueuedProposal: crate::storage::traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::PublicError>;

    /// Returns the TreeSync tree for the group with group id `group_id`.
    async fn tree<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        TreeSync: crate::storage::traits::TreeSync<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::PublicError>;

    /// Returns the group context for the group with group id `group_id`.
    async fn group_context<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        GroupContext: crate::storage::traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::PublicError>;

    /// Returns the interim transcript hash for the group with group id `group_id`.
    async fn interim_transcript_hash<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        InterimTranscriptHash: crate::storage::traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::PublicError>;

    /// Returns the confirmation tag for the group with group id `group_id`.
    async fn confirmation_tag<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ConfirmationTag: crate::storage::traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::PublicError>;

    /// Deletes the tree from storage
    async fn delete_tree<GroupId: crate::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError>;

    /// Deletes the confirmation tag from storage
    async fn delete_confirmation_tag<GroupId: crate::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError>;

    /// Deletes the group context for the group with given id
    async fn delete_context<GroupId: crate::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError>;

    /// Deletes the interim transcript hash for the group with given id
    async fn delete_interim_transcript_hash<GroupId: crate::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError>;

    /// Removes an individual proposal from the proposal queue of the group with the provided id
    async fn remove_proposal<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ProposalRef: crate::storage::traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::PublicError>;

    /// Clear the proposal queue for the group with the given id.
    async fn clear_proposal_queue<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ProposalRef: crate::storage::traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError>;
}

#[maybe_async::maybe_async(AFIT)]
impl<T, const VERSION: u16> PublicStorageProvider<VERSION> for T
where
    T: StorageProvider<VERSION>,
{
    type PublicError = <T as StorageProvider<VERSION>>::Error;

    async fn write_tree<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        TreeSync: crate::storage::traits::TreeSync<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::write_tree(self, group_id, tree).await
    }

    async fn write_interim_transcript_hash<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        InterimTranscriptHash: crate::storage::traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::write_interim_transcript_hash(
            self,
            group_id,
            interim_transcript_hash,
        )
        .await
    }

    async fn write_context<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        GroupContext: crate::storage::traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::write_context(self, group_id, group_context).await
    }

    async fn write_confirmation_tag<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ConfirmationTag: crate::storage::traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::write_confirmation_tag(self, group_id, confirmation_tag)
            .await
    }

    async fn queue_proposal<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ProposalRef: crate::storage::traits::ProposalRef<VERSION>,
        QueuedProposal: crate::storage::traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::queue_proposal(self, group_id, proposal_ref, proposal)
            .await
    }

    async fn queued_proposals<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ProposalRef: crate::storage::traits::ProposalRef<VERSION>,
        QueuedProposal: crate::storage::traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::PublicError> {
        <Self as StorageProvider<VERSION>>::queued_proposals(self, group_id).await
    }

    async fn tree<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        TreeSync: crate::storage::traits::TreeSync<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::PublicError> {
        <Self as StorageProvider<VERSION>>::tree(self, group_id).await
    }

    async fn group_context<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        GroupContext: crate::storage::traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::PublicError> {
        <Self as StorageProvider<VERSION>>::group_context(self, group_id).await
    }

    async fn interim_transcript_hash<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        InterimTranscriptHash: crate::storage::traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::PublicError> {
        <Self as StorageProvider<VERSION>>::interim_transcript_hash(self, group_id).await
    }

    async fn confirmation_tag<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ConfirmationTag: crate::storage::traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::PublicError> {
        <Self as StorageProvider<VERSION>>::confirmation_tag(self, group_id).await
    }

    async fn delete_tree<GroupId: crate::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::delete_tree(self, group_id).await
    }

    async fn delete_confirmation_tag<GroupId: crate::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::delete_confirmation_tag(self, group_id).await
    }

    async fn delete_context<GroupId: crate::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::delete_context(self, group_id).await
    }

    async fn delete_interim_transcript_hash<GroupId: crate::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::delete_interim_transcript_hash(self, group_id).await
    }

    async fn remove_proposal<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ProposalRef: crate::storage::traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::remove_proposal(self, group_id, proposal_ref).await
    }

    async fn clear_proposal_queue<
        GroupId: crate::storage::traits::GroupId<VERSION>,
        ProposalRef: crate::storage::traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::PublicError> {
        <Self as StorageProvider<VERSION>>::clear_proposal_queue::<GroupId, ProposalRef>(
            self, group_id,
        )
        .await
    }
}
