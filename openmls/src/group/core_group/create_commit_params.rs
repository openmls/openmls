//! Builder for [CreateCommitParams] that is used in [CoreGroup::create_commit()]

use super::{proposals::ProposalStore, *};
use crate::ciphersuite::SignaturePublicKey;

/// Can be used to denote the type of a commit.
#[derive(Debug, Copy, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum CommitType {
    External,
    Member,
}

pub(crate) struct CreateCommitParams<'a> {
    framing_parameters: FramingParameters<'a>, // Mandatory
    proposal_store: &'a ProposalStore,         // Mandatory
    inline_proposals: Vec<Proposal>,           // Optional
    force_self_update: bool,                   // Optional
    commit_type: CommitType,                   // Optional (default is `Member`)
    signature_key: Option<SignaturePublicKey>, // Mandatory for external commits
    credential: Option<Credential>,            // Mandatory for external commits
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
        framing_parameters: FramingParameters,
    ) -> TempBuilderCCPM1 {
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
                signature_key: None,
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
    pub(crate) fn commit_type(mut self, commit_type: CommitType) -> Self {
        self.ccp.commit_type = commit_type;
        self
    }
    pub(crate) fn signature_key(mut self, signature_key: SignaturePublicKey) -> Self {
        self.ccp.signature_key = Some(signature_key);
        self
    }
    pub(crate) fn credential(mut self, credential: Credential) -> Self {
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
    pub(crate) fn signature_key(&mut self) -> Option<SignaturePublicKey> {
        self.signature_key.take()
    }
    pub(crate) fn credential(&mut self) -> Option<Credential> {
        self.credential.take()
    }
}
