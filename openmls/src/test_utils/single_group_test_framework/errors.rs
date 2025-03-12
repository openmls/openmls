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
#[derive(Debug)]
pub enum TestError<StorageError> {
    CreateCommit(CreateCommitError),
    CommitBuilderStage(CommitBuilderStageError<StorageError>),
    NewGroup(NewGroupError<StorageError>),
    ProcessMessage(ProcessMessageError),
    Welcome(WelcomeError<StorageError>),
    ProtocolMessage(ProtocolMessageError),
    MergeCommit(MergeCommitError<StorageError>),
    CommitToPendingProposals(CommitToPendingProposalsError<StorageError>),
    NoSuchMember,
}

impl<StorageError> From<CreateCommitError> for TestError<StorageError> {
    fn from(e: CreateCommitError) -> Self {
        TestError::CreateCommit(e)
    }
}
impl<StorageError> From<CommitBuilderStageError<StorageError>> for TestError<StorageError> {
    fn from(e: CommitBuilderStageError<StorageError>) -> Self {
        TestError::CommitBuilderStage(e)
    }
}

impl<StorageError> From<CommitToPendingProposalsError<StorageError>> for TestError<StorageError> {
    fn from(e: CommitToPendingProposalsError<StorageError>) -> Self {
        TestError::CommitToPendingProposals(e)
    }
}

impl<StorageError> From<NewGroupError<StorageError>> for TestError<StorageError> {
    fn from(e: NewGroupError<StorageError>) -> Self {
        TestError::NewGroup(e)
    }
}
impl<StorageError> From<WelcomeError<StorageError>> for TestError<StorageError> {
    fn from(e: WelcomeError<StorageError>) -> Self {
        TestError::Welcome(e)
    }
}

impl<StorageError> From<ProcessMessageError> for TestError<StorageError> {
    fn from(e: ProcessMessageError) -> Self {
        TestError::ProcessMessage(e)
    }
}

impl<StorageError> From<ProtocolMessageError> for TestError<StorageError> {
    fn from(e: ProtocolMessageError) -> Self {
        TestError::ProtocolMessage(e)
    }
}

impl<StorageError> From<MergeCommitError<StorageError>> for TestError<StorageError> {
    fn from(e: MergeCommitError<StorageError>) -> Self {
        TestError::MergeCommit(e)
    }
}
