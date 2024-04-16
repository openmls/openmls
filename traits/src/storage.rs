use serde::{de::DeserializeOwned, Serialize};

pub const VERSION_V1: usize = 1;

pub trait Types<const VERSION: usize>: Default {
    type QueuedProposal: QueuedProposalEntity<VERSION>;
    type GroupId: GroupIdKey<VERSION>;
    type ProposalRef: ProposalRefKey<VERSION> + ProposalRefEntity<VERSION>;
    type TreeSync: TreeSyncEntity<VERSION>;
    type GroupContext: GroupContextEntity<VERSION>;
    type InterimTranscriptHash: InterimTranscriptHashEntity<VERSION>;
    type ConfirmationTag: ConfirmationTagEntity<VERSION>;
}

pub trait GetError: core::fmt::Debug + std::error::Error + PartialEq {
    fn error_kind(&self) -> GetErrorKind;
}

pub trait UpdateError: core::fmt::Debug + std::error::Error + PartialEq {
    fn error_kind(&self) -> UpdateErrorKind;
}

pub mod v1 {
    use super::*;

    pub trait Types: super::Types<VERSION_V1> {}

    impl<T: super::Types<VERSION_V1>> Types for T {}

    pub trait StorageProvider {
        // source for errors
        type GetError: GetError;
        type UpdateError: UpdateError;
        type Types: Types;

        // update functions, single and batched
        fn apply_update(&self, update: Update<Self::Types>) -> Result<(), Self::UpdateError>;
        fn apply_updates(&self, update: Vec<Update<Self::Types>>) -> Result<(), Self::UpdateError>;

        // getter
        fn get_queued_proposal_refs(
            &self,
            group_id: &<Self::Types as super::Types<VERSION_V1>>::GroupId,
        ) -> Result<Vec<<Self::Types as super::Types<VERSION_V1>>::ProposalRef>, Self::GetError>;

        fn get_queued_proposals(
            &self,
            group_id: &<Self::Types as super::Types<VERSION_V1>>::GroupId,
        ) -> Result<Vec<<Self::Types as super::Types<VERSION_V1>>::QueuedProposal>, Self::GetError>;

        fn get_treesync(
            &self,
            group_id: &<Self::Types as super::Types<VERSION_V1>>::GroupId,
        ) -> Result<<Self::Types as super::Types<VERSION_V1>>::TreeSync, Self::GetError>;

        fn get_group_context(
            &self,
            group_id: &<Self::Types as super::Types<VERSION_V1>>::GroupId,
        ) -> Result<<Self::Types as super::Types<VERSION_V1>>::GroupContext, Self::GetError>;

        fn get_interim_transcript_hash(
            &self,
            group_id: &<Self::Types as super::Types<VERSION_V1>>::GroupId,
        ) -> Result<<Self::Types as super::Types<VERSION_V1>>::InterimTranscriptHash, Self::GetError>;

        fn get_confirmation_tag(
            &self,
            group_id: &<Self::Types as super::Types<VERSION_V1>>::GroupId,
        ) -> Result<<Self::Types as super::Types<VERSION_V1>>::ConfirmationTag, Self::GetError>;
    }

    // contains the different types of updates
    pub enum Update<T: Types> {
        QueueProposal(T::GroupId, T::ProposalRef, T::QueuedProposal),
        WriteTreeSync(T::GroupId, T::TreeSync),
        WriteGroupContext(T::GroupId, T::GroupContext),
        WriteInterimTranscriptHash(T::GroupId, T::InterimTranscriptHash),
        WriteConfirmationTag(T::GroupId, T::ConfirmationTag),
    }
}

// base traits for keys and values
pub trait Key<const VERSION: usize>: Serialize {}
pub trait Entity<const VERSION: usize>: Serialize + DeserializeOwned {}

// in the following we define specific traits for Keys and Entities. That way
// we can don't sacrifice type safety in the implementations of the storage provider.
// note that there are types that are used both as keys and as entities.

// traits for keys, one per data type
pub trait GroupIdKey<const VERSION: usize>: Key<VERSION> {}
pub trait ProposalRefKey<const VERSION: usize>: Key<VERSION> {}

// traits for entity, one per type
pub trait QueuedProposalEntity<const VERSION: usize>: Entity<VERSION> {}
pub trait ProposalRefEntity<const VERSION: usize>: Entity<VERSION> {}
pub trait TreeSyncEntity<const VERSION: usize>: Entity<VERSION> {}
pub trait GroupContextEntity<const VERSION: usize>: Entity<VERSION> {}
pub trait InterimTranscriptHashEntity<const VERSION: usize>: Entity<VERSION> {}
pub trait ConfirmationTagEntity<const VERSION: usize>: Entity<VERSION> {}

// errors
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GetErrorKind {
    NotFound,
    Encoding,
    Internal,
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UpdateErrorKind {
    Encoding,
    Internal,
    LockPoisoned,
    AlreadyExists,
}
