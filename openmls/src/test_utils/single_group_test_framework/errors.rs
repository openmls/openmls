use thiserror::Error;

use crate::prelude::{commit_builder::*, *};
pub use crate::utils::*;

pub use openmls_traits::{
    storage::{StorageProvider as StorageProviderTrait, CURRENT_VERSION},
    types::{Ciphersuite, HpkeKeyPair},
    OpenMlsProvider,
};

// type alias for `TestError`
pub type GroupError<Provider> =
    TestError<<<Provider as OpenMlsProvider>::StorageProvider as StorageProviderTrait<CURRENT_VERSION>>::Error>;
#[derive(Error, Debug)]
pub enum TestError<StorageError> {
    AddMembers(#[from] AddMembersError<StorageError>),
    CreateCommit(#[from] CreateCommitError),
    CommitBuilderStage(#[from] CommitBuilderStageError<StorageError>),
    NewGroup(#[from] NewGroupError<StorageError>),
    ProcessMessage(#[from] ProcessMessageError),
    Welcome(#[from] WelcomeError<StorageError>),
    ProtocolMessage(#[from] ProtocolMessageError),
    MergeCommit(#[from] MergeCommitError<StorageError>),
    CommitToPendingProposals(#[from] CommitToPendingProposalsError<StorageError>),
    NoSuchMember,
}
