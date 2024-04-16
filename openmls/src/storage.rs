pub use v1::OpenMlsTypes;

const CURRENT_VERSION: usize = 1;

pub trait StorageProvider:
    openmls_traits::storage::v1::StorageProvider<Types = OpenMlsTypes>
{
}

impl<P: openmls_traits::storage::v1::StorageProvider<Types = OpenMlsTypes>> StorageProvider for P {}

pub trait RefinedProvider:
    openmls_traits::OpenMlsProvider<StorageProvider = Self::Storage>
{
    type Storage: StorageProvider;
}

impl<SP: StorageProvider, OP: openmls_traits::OpenMlsProvider<StorageProvider = SP>> RefinedProvider
    for OP
{
    type Storage = SP;
}

pub mod v1 {
    pub const VERSION: usize = 1;

    #[derive(Debug, Clone, Default)]
    pub struct OpenMlsTypes;

    use openmls_traits::storage::*;

    use crate::ciphersuite::hash_ref::ProposalRef;
    use crate::group::GroupContext;
    use crate::group::GroupId;
    use crate::group::InterimTranscriptHash;
    use crate::group::QueuedProposal;
    use crate::messages::ConfirmationTag;
    use crate::treesync::TreeSync;

    impl Entity<VERSION> for QueuedProposal {}
    impl QueuedProposalEntity<VERSION> for QueuedProposal {}

    impl Entity<VERSION> for TreeSync {}
    impl TreeSyncEntity<VERSION> for TreeSync {}

    impl Key<VERSION> for GroupId {}
    impl GroupIdKey<VERSION> for GroupId {}

    impl Key<VERSION> for ProposalRef {}
    impl Entity<VERSION> for ProposalRef {}
    impl ProposalRefKey<VERSION> for ProposalRef {}
    impl ProposalRefEntity<VERSION> for ProposalRef {}

    impl Entity<VERSION> for GroupContext {}
    impl GroupContextEntity<VERSION> for GroupContext {}

    impl Entity<VERSION> for InterimTranscriptHash {}
    impl InterimTranscriptHashEntity<VERSION> for InterimTranscriptHash {}

    impl Entity<VERSION> for ConfirmationTag {}
    impl ConfirmationTagEntity<VERSION> for ConfirmationTag {}

    impl Types<VERSION> for OpenMlsTypes {
        type QueuedProposal = QueuedProposal;
        type GroupId = GroupId;
        type ProposalRef = ProposalRef;
        type TreeSync = TreeSync;
        type GroupContext = GroupContext;
        type InterimTranscriptHash = InterimTranscriptHash;
        type ConfirmationTag = ConfirmationTag;
    }
}
