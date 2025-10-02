use openmls_traits::storage::{CURRENT_VERSION, Entity};

pub(crate) struct StorableProposal<
    Proposal: Entity<CURRENT_VERSION>,
    ProposalRef: Entity<CURRENT_VERSION>,
>(pub ProposalRef, pub Proposal);

pub(super) struct StorableProposalRef<
    'a,
    Proposal: Entity<CURRENT_VERSION>,
    ProposalRef: Entity<CURRENT_VERSION>,
>(pub &'a ProposalRef, pub &'a Proposal);
