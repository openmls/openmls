use openmls_traits::crypto::OpenMlsCrypto;

use crate::{
    error::LibraryError,
    framing::{mls_auth_content::AuthenticatedContent, mls_content::FramedContentBody},
    spec_types::{
        proposals::{Proposal, ProposalOrRefType, ProposalRef, Sender},
        Ciphersuite,
    },
};

/// Alternative representation of a Proposal, where the sender is extracted from
/// the encapsulating PublicMessage and the ProposalRef is attached.
#[derive(Clone, Debug, PartialEq)]
pub struct QueuedProposal {
    pub(in crate::spec_types) proposal: Proposal,
    pub(in crate::spec_types) proposal_reference: ProposalRef,
    pub(in crate::spec_types) sender: Sender,

    pub(in crate::spec_types) proposal_or_ref_type: ProposalOrRefType,
}

impl QueuedProposal {
    /// Creates a new [QueuedProposal] from an [PublicMessage]
    pub(crate) fn from_authenticated_content_by_ref(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        public_message: AuthenticatedContent,
    ) -> Result<Self, LibraryError> {
        Self::from_authenticated_content(
            ciphersuite,
            crypto,
            public_message,
            ProposalOrRefType::Reference,
        )
    }

    /// Creates a new [QueuedProposal] from an [PublicMessage]
    pub(crate) fn from_authenticated_content_by_value(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        public_message: AuthenticatedContent,
    ) -> Result<Self, LibraryError> {
        Self::from_authenticated_content(
            ciphersuite,
            crypto,
            public_message,
            ProposalOrRefType::Proposal,
        )
    }

    /// Creates a new [QueuedProposal] from an [PublicMessage]
    pub(crate) fn from_authenticated_content(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        public_message: AuthenticatedContent,
        proposal_or_ref_type: ProposalOrRefType,
    ) -> Result<Self, LibraryError> {
        let proposal_reference =
            ProposalRef::from_authenticated_content_by_ref(crypto, ciphersuite, &public_message)
                .map_err(|_| LibraryError::custom("Could not calculate `ProposalRef`."))?;

        let (body, sender) = public_message.into_body_and_sender();

        let proposal = match body {
            FramedContentBody::Proposal(p) => p,
            _ => return Err(LibraryError::custom("Wrong content type")),
        };

        Ok(Self {
            proposal,
            proposal_reference,
            sender,
            proposal_or_ref_type,
        })
    }

    /// Creates a new [QueuedProposal] from a [Proposal] and [Sender]
    ///
    /// Note: We should calculate the proposal ref by hashing the authenticated
    /// content but can't do this here without major refactoring. Thus, we
    /// use an internal `from_raw_proposal` hash.
    pub(crate) fn from_proposal_and_sender(
        ciphersuite: Ciphersuite,
        crypto: &impl OpenMlsCrypto,
        proposal: Proposal,
        sender: &Sender,
    ) -> Result<Self, LibraryError> {
        let proposal_reference = ProposalRef::from_raw_proposal(ciphersuite, crypto, &proposal)?;
        Ok(Self {
            proposal,
            proposal_reference,
            sender: sender.clone(),
            proposal_or_ref_type: ProposalOrRefType::Proposal,
        })
    }

    /// Returns the `Proposal` as a reference
    pub fn proposal(&self) -> &Proposal {
        &self.proposal
    }
    /// Returns the `ProposalRef`.
    pub(crate) fn proposal_reference(&self) -> ProposalRef {
        self.proposal_reference.clone()
    }
    /// Returns the `ProposalOrRefType`.
    pub fn proposal_or_ref_type(&self) -> ProposalOrRefType {
        self.proposal_or_ref_type
    }
    /// Returns the `Sender` as a reference
    pub fn sender(&self) -> &Sender {
        &self.sender
    }

    pub(crate) fn spec_proposal(&self) -> openmls_spec_types::proposals::Proposal {
        self.proposal.clone().into()
    }

    pub(crate) fn spec_proposal_ref(&self) -> openmls_spec_types::proposals::ProposalRef {
        openmls_spec_types::proposals::ProposalRef(self.proposal_reference.clone().into())
    }

    pub(crate) fn spec_sender(&self) -> openmls_spec_types::proposals::Sender {
        self.sender.clone().into()
    }

    pub(crate) fn spec_proposal_or_ref_type(
        &self,
    ) -> openmls_spec_types::proposals::ProposalOrRefType {
        self.proposal_or_ref_type.into()
    }
}
