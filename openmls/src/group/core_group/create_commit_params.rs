//! Builder for [CreateCommitParams] that is used in [CoreGroup::create_commit()]

use serde::{Deserialize, Serialize};

use crate::{
    credentials::CredentialWithKey, framing::FramingParameters, messages::proposals::Proposal,
};

#[cfg(doc)]
use super::CoreGroup;
use super::LeafNodeParameters;

/// Can be used to denote the type of a commit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) enum CommitType {
    External(CredentialWithKey),
    Member,
}

pub(crate) struct CreateCommitParams<'a> {
    framing_parameters: FramingParameters<'a>, // Mandatory
    inline_proposals: Vec<Proposal>,           // Optional
    force_self_update: bool,                   // Optional
    commit_type: CommitType,                   // Optional (default is `Member`)
    leaf_node_parameters: LeafNodeParameters,  // Optional
}

pub(crate) struct TempBuilderCCPM0 {}

pub(crate) struct CreateCommitParamsBuilder<'a> {
    ccp: CreateCommitParams<'a>,
}

impl TempBuilderCCPM0 {
    pub(crate) fn framing_parameters(
        self,
        framing_parameters: FramingParameters,
    ) -> CreateCommitParamsBuilder {
        CreateCommitParamsBuilder {
            ccp: CreateCommitParams {
                framing_parameters,
                inline_proposals: vec![],
                force_self_update: true,
                commit_type: CommitType::Member,
                leaf_node_parameters: LeafNodeParameters::default(),
            },
        }
    }
}

impl<'a> CreateCommitParamsBuilder<'a> {
    pub(crate) fn inline_proposals(mut self, inline_proposals: Vec<Proposal>) -> Self {
        self.ccp.inline_proposals = inline_proposals;
        self
    }
    pub(crate) fn force_self_update(mut self, force_self_update: bool) -> Self {
        self.ccp.force_self_update = force_self_update;
        self
    }
    pub(crate) fn commit_type(mut self, commit_type: CommitType) -> Self {
        self.ccp.commit_type = commit_type;
        self
    }
    pub(crate) fn leaf_node_parameters(mut self, leaf_node_parameters: LeafNodeParameters) -> Self {
        self.ccp.leaf_node_parameters = leaf_node_parameters;
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
    pub(crate) fn inline_proposals(&self) -> &[Proposal] {
        &self.inline_proposals
    }
    pub(crate) fn set_inline_proposals(&mut self, inline_proposals: Vec<Proposal>) {
        self.inline_proposals = inline_proposals;
    }
    pub(crate) fn force_self_update(&self) -> bool {
        self.force_self_update
    }
    pub(crate) fn commit_type(&self) -> &CommitType {
        &self.commit_type
    }
    pub(crate) fn leaf_node_parameters(&self) -> &LeafNodeParameters {
        &self.leaf_node_parameters
    }
}
