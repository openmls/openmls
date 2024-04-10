use serde::{de::DeserializeOwned, Serialize};

pub trait Types<const VERSION: usize> {
    type QueuedProposal: QueuedProposalEntity<VERSION>;
    type GroupId: GroupIdKey<VERSION>;
    type ProposalRef: ProposalRefKey<VERSION> + ProposalRefEntity<VERSION>;
}

pub trait StorageProvider<const VERSION: usize> {
    // source for errors
    type GetErrorSource: core::fmt::Debug;
    type UpdateErrorSource: core::fmt::Debug;
    type Types: Types<VERSION>;

    // update functions, single and batched
    fn apply_update(
        &mut self,
        update: Update<VERSION, Self::Types>,
    ) -> Result<(), UpdateError<Self::UpdateErrorSource>>;
    fn apply_updates(
        &mut self,
        update: Vec<Update<VERSION, Self::Types>>,
    ) -> Result<(), UpdateError<Self::UpdateErrorSource>>;

    // getter
    fn get_queued_proposal_refs(
        &self,
        group_id: &<Self::Types as Types<VERSION>>::GroupId,
    ) -> Result<Vec<<Self::Types as Types<VERSION>>::ProposalRef>, GetError<Self::GetErrorSource>>;

    fn get_queued_proposals(
        &self,
        group_id: &<Self::Types as Types<VERSION>>::GroupId,
    ) -> Result<Vec<<Self::Types as Types<VERSION>>::QueuedProposal>, GetError<Self::GetErrorSource>>;
}

// contains the different types of updates
pub enum Update<const VERSION: usize, T: Types<VERSION>> {
    QueueProposal(T::GroupId, T::ProposalRef, T::QueuedProposal),
}

// base traits for keys and values
pub trait Key<const VERSION: usize>: Serialize {}
pub trait Entity<const VERSION: usize>: Serialize + DeserializeOwned {}

// traits for keys, one per data type
pub trait GroupIdKey<const VERSION: usize>: Key<VERSION> {}
pub trait ProposalRefKey<const VERSION: usize>: Key<VERSION> {}

// traits for entity, one per type
pub trait QueuedProposalEntity<const VERSION: usize>: Entity<VERSION> {}
pub trait ProposalRefEntity<const VERSION: usize>: Entity<VERSION> {}

// errors
pub enum GetErrorKind {
    NotFound,
    Encoding,
    Internal,
}

pub struct GetError<E> {
    pub kind: GetErrorKind,
    pub source: E,
}

pub enum UpdateErrorKind {
    Encoding,
    Internal,
}

pub struct UpdateError<E> {
    pub kind: UpdateErrorKind,
    pub source: E,
}
