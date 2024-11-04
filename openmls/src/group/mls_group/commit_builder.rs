//! This module contains the types for building commits.
//!
//! A living design doc can be found here: https://md.cryspen.com/s/TqZXcU-gA
//!
//! we might need multiple builder types to restrict the operations (methods that can be called),
//! but that's not clear yet.
//!
//!   Can also add a (const) generic param and only impl functions for some cases
//!
//!
//! What are the general phases?
//!
//!  - build all the proposals
//!    - do some of the proposals also need a builder or can we just add them?
//!    - does this already need to lock the group?
//!      - maybe; otherwise we can build two confilicting commits in parallel
//!        - we still should validate the commit when staging it, but ideally all possible issues
//!          should have been caught before
//!          - if we can make sure that all problems have been caught, the staging can just not
//!            return an error
//!  - do the signing (io!) - consume the group
//!  - stage the commit - release the group
//!
//!  - operations for step 0:
//!    - add new proposals
//!    - add select proposals by ref (that are in group's quuee)
//!    - add all proposals from the group's quuee

use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer};

use crate::{
    ciphersuite::hash_ref::ProposalRef,
    group::{
        create_commit::{CommitType, CreateCommitParams, CreateCommitParamsBuilder},
        ProposalQueue,
    },
    key_packages::KeyPackage,
    storage::StorageProvider,
};

use super::{AddProposal, CreateCommitResult, MlsGroup, Proposal};

/// This step is about populating the builder
struct Initial;

// TODO: should there be an intermediate step for validation?

/// This step is after we signed and constructed the commit, but before we staged it
struct ValidatedRegular;

struct ValidatedExternal;

#[derive(Debug)]
pub(crate) struct CommitBuilder<'a, T> {
    group: &'a mut MlsGroup,
    own_proposals: Vec<Proposal>,
    proposals: ProposalQueue,
    self_update_key_package: Option<KeyPackage>,
    included_proposal_refs: Vec<ProposalRef>,
    force_self_update: bool,

    /// Whether or not to clear the proposal queue of the group when staging the commit. Needs to
    /// be done when we include the commits that have already been queued.
    clear_proposal_queue: bool,

    _stage: T,
}

impl<'a> CommitBuilder<'a, Initial> {
    fn new(group: &'a mut MlsGroup) -> Self {
        Self {
            group,
            own_proposals: vec![],
            proposals: ProposalQueue::default(),
            self_update_key_package: None,
            clear_proposal_queue: false,
            included_proposal_refs: vec![],
            force_self_update: false,
            _stage: Initial,
        }
    }

    fn include_queued_proposals(mut self) -> Self {
        // TODO: maybe skip proposals as described in
        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.2-3.4
        for proposal in self.group.proposal_store().proposals() {
            self.proposals.add(proposal.clone());
        }
        self.clear_proposal_queue = true;
        self
    }

    fn propose_add(mut self, key_package: KeyPackage) -> Self {
        // TODO: validation? or do it later?
        self.own_proposals
            .push(Proposal::Add(AddProposal { key_package }));
        self
    }

    fn validate_regular(self) -> CommitBuilder<'a, ValidatedRegular> {
        let Self {
            group,
            own_proposals,
            proposals,
            self_update_key_package,
            included_proposal_refs,
            force_self_update,
            clear_proposal_queue,
            _stage,
        } = self;

        // TODO: validate proposal list
        //          this is a bit annoying; the easiest way would be to turn all own_proposals into
        //          full QueuedProposals and process them using the existing validation logic.
        //          However. that would require us to pointlessly sign them here, just so they are
        //          in the right format. I think that might even be what we are already doing,
        //          but.. well, it's not great.

        CommitBuilder {
            own_proposals,
            group,
            proposals,
            clear_proposal_queue,
            self_update_key_package,
            included_proposal_refs,
            force_self_update,

            _stage: ValidatedRegular,
        }
    }
}

impl<'a> CommitBuilder<'a, ValidatedRegular> {
    fn build(
        self,
        crypto: &impl OpenMlsCrypto,
        storage: &impl StorageProvider,
        signer: &impl Signer,
    ) -> Result<CreateCommitResult, ()> {
        let create_commit_params = CreateCommitParams::builder()
            .framing_parameters(self.group.framing_parameters())
            .force_self_update(self.force_self_update)
            .commit_type(CommitType::Member)
            .build();

        // TODO: actually build the commit. It's not clear whether the create commit params really
        // help us here, because the create_commit function sort of does all the things we want to
        // do in this builder.
        // maybe we can just call that function for now and gradually move the functionality in
        // here? Or should we rather move the functionality here and re-implement the old API using
        // this builder instead?

        todo!()
    }
}
