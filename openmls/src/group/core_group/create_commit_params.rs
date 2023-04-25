//! Builder for [CreateCommitParams] that is used in [CoreGroup::create_commit()]

use openmls_traits::credential::OpenMlsCredential;
use serde::{Deserialize, Serialize};

use crate::{framing::FramingParameters, group::ProposalStore, messages::proposals::Proposal};

#[cfg(doc)]
use super::CoreGroup;

/// Can be used to denote the type of a commit.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum CommitType {
    External,
    Member,
}

pub(crate) struct CreateCommitParams<'a> {
    framing_parameters: FramingParameters<'a>,     // Mandatory
    proposal_store: &'a ProposalStore,             // Mandatory
    inline_proposals: Vec<Proposal>,               // Optional
    force_self_update: bool,                       // Optional
    commit_type: CommitType,                       // Optional (default is `Member`)
    credential: Option<&'a dyn OpenMlsCredential>, // Mandatory for external commits
}

pub(crate) struct TempBuilderCCPM0 {}

pub(crate) struct TempBuilderCCPM1<'a> {
    framing_parameters: FramingParameters<'a>,
}

pub(crate) struct CreateCommitParamsBuilder<'a> {
    ccp: CreateCommitParams<'a>,
}

impl TempBuilderCCPM0 {
    pub(crate) fn framing_parameters(
        self,
        framing_parameters: FramingParameters<'_>,
    ) -> TempBuilderCCPM1<'_> {
        TempBuilderCCPM1 { framing_parameters }
    }
}

impl<'a> TempBuilderCCPM1<'a> {
    pub(crate) fn proposal_store(
        self,
        proposal_store: &'a ProposalStore,
    ) -> CreateCommitParamsBuilder<'a> {
        CreateCommitParamsBuilder {
            ccp: CreateCommitParams {
                framing_parameters: self.framing_parameters,
                proposal_store,
                inline_proposals: vec![],
                force_self_update: true,
                commit_type: CommitType::Member,
                credential: None,
            },
        }
    }
}

impl<'a> CreateCommitParamsBuilder<'a> {
    pub(crate) fn inline_proposals(mut self, inline_proposals: Vec<Proposal>) -> Self {
        self.ccp.inline_proposals = inline_proposals;
        self
    }
    #[cfg(test)]
    pub(crate) fn force_self_update(mut self, force_self_update: bool) -> Self {
        self.ccp.force_self_update = force_self_update;
        self
    }
    pub(crate) fn credential(mut self, credential: &'a dyn OpenMlsCredential) -> Self {
        self.ccp.credential = Some(credential);
        self
    }
    pub(crate) fn build(self) -> CreateCommitParams<'a> {
        self.ccp
    }
}

impl<'a> CreateCommitParams<'a> {
    pub(crate) fn builder() -> TempBuilderCCPM0 {
        TempBuilderCCPM0 {}
    }
    pub(crate) fn framing_parameters(&self) -> &FramingParameters {
        &self.framing_parameters
    }
    pub(crate) fn proposal_store(&self) -> &ProposalStore {
        self.proposal_store
    }
    pub(crate) fn inline_proposals(&self) -> &[Proposal] {
        &self.inline_proposals
    }
    pub(crate) fn force_self_update(&self) -> bool {
        self.force_self_update
    }
    pub(crate) fn commit_type(&self) -> CommitType {
        self.commit_type
    }
    pub(crate) fn credential(&self) -> Option<&dyn OpenMlsCredential> {
        self.credential
    }
    pub(crate) fn set_commit_type(&mut self, commit_type: CommitType) {
        self.commit_type = commit_type;
    }
    pub(crate) fn set_inline_proposal(&mut self, inline_proposals: Vec<Proposal>) {
        self.inline_proposals = inline_proposals;
    }
}
