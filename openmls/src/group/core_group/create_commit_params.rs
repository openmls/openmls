//! Builder for [CreateCommitParams] that is used in [CoreGroup::create_commit()]

use super::{proposals::ProposalStore, *};

/// Can be used to denote the type of a commit.
#[derive(Debug, Copy, Clone)]
pub enum CommitType {
    External,
    Member,
}

pub struct CreateCommitParams<'a> {
    framing_parameters: FramingParameters<'a>, // Mandatory
    credential_bundle: &'a CredentialBundle,   // Mandatory
    proposal_store: &'a ProposalStore,         // Mandatory
    inline_proposals: Vec<Proposal>,           // Optional
    force_self_update: bool,                   // Optional
    commit_type: CommitType,                   // Optional (default is `Member`)
}

pub struct TempBuilderCCPM0 {}

pub struct TempBuilderCCPM1<'a> {
    framing_parameters: FramingParameters<'a>,
}

pub struct TempBuilderCCPM2<'a> {
    framing_parameters: FramingParameters<'a>,
    credential_bundle: &'a CredentialBundle,
}

pub struct CreateCommitParamsBuilder<'a> {
    ccp: CreateCommitParams<'a>,
}

impl TempBuilderCCPM0 {
    pub fn framing_parameters(self, framing_parameters: FramingParameters) -> TempBuilderCCPM1 {
        TempBuilderCCPM1 { framing_parameters }
    }
}

impl<'a> TempBuilderCCPM1<'a> {
    pub fn credential_bundle(
        self,
        credential_bundle: &'a CredentialBundle,
    ) -> TempBuilderCCPM2<'a> {
        TempBuilderCCPM2 {
            framing_parameters: self.framing_parameters,
            credential_bundle,
        }
    }
}

impl<'a> TempBuilderCCPM2<'a> {
    pub fn proposal_store(
        self,
        proposal_store: &'a ProposalStore,
    ) -> CreateCommitParamsBuilder<'a> {
        CreateCommitParamsBuilder {
            ccp: CreateCommitParams {
                framing_parameters: self.framing_parameters,
                credential_bundle: self.credential_bundle,
                proposal_store,
                inline_proposals: vec![],
                force_self_update: true,
                commit_type: CommitType::Member,
            },
        }
    }
}

impl<'a> CreateCommitParamsBuilder<'a> {
    pub fn inline_proposals(mut self, inline_proposals: Vec<Proposal>) -> Self {
        self.ccp.inline_proposals = inline_proposals;
        self
    }
    #[cfg(any(feature = "test-utils", test))]
    pub fn force_self_update(mut self, force_self_update: bool) -> Self {
        self.ccp.force_self_update = force_self_update;
        self
    }
    #[cfg(any(feature = "test-utils", test))]
    pub fn commit_type(mut self, commit_type: CommitType) -> Self {
        self.ccp.commit_type = commit_type;
        self
    }
    pub fn build(self) -> CreateCommitParams<'a> {
        self.ccp
    }
}

impl<'a> CreateCommitParams<'a> {
    pub fn builder() -> TempBuilderCCPM0 {
        TempBuilderCCPM0 {}
    }
    pub fn framing_parameters(&self) -> &FramingParameters {
        &self.framing_parameters
    }
    pub fn credential_bundle(&self) -> &CredentialBundle {
        self.credential_bundle
    }
    pub fn proposal_store(&self) -> &ProposalStore {
        self.proposal_store
    }
    pub fn inline_proposals(&self) -> &[Proposal] {
        &self.inline_proposals
    }
    pub fn force_self_update(&self) -> bool {
        self.force_self_update
    }
    pub fn commit_type(&self) -> CommitType {
        self.commit_type
    }
}
