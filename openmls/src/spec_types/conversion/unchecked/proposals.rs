use crate::spec_types as private_types;
use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_spec_types as public_types;

impl PrivateSpecType for private_types::proposals::ProposalType {
    type Public = public_types::proposals::ProposalType;
    fn from_public_unchecked(proposal_type: public_types::proposals::ProposalType) -> Self {
        match proposal_type {
            public_types::proposals::ProposalType::Add => Self::Add,
            public_types::proposals::ProposalType::Update => Self::Update,
            public_types::proposals::ProposalType::Remove => Self::Remove,
            public_types::proposals::ProposalType::PreSharedKey => Self::PreSharedKey,
            public_types::proposals::ProposalType::Reinit => Self::Reinit,
            public_types::proposals::ProposalType::ExternalInit => Self::ExternalInit,
            public_types::proposals::ProposalType::GroupContextExtensions => {
                Self::GroupContextExtensions
            }
            public_types::proposals::ProposalType::AppAck => Self::AppAck,
            public_types::proposals::ProposalType::Unknown(n) => Self::Unknown(n),
        }
    }
}

impl PrivateSpecType for private_types::proposals::Proposal {
    type Public = public_types::proposals::Proposal;
    fn from_public_unchecked(proposal: public_types::proposals::Proposal) -> Self {
        match proposal {
            public_types::proposals::Proposal::Add(prop) => {
                private_types::proposals::Proposal::Add(
                    private_types::proposals::AddProposal::from_public_unchecked(prop),
                )
            }
            public_types::proposals::Proposal::Update(prop) => {
                private_types::proposals::Proposal::Update(
                    private_types::proposals::UpdateProposal::from_public_unchecked(prop),
                )
            }
            public_types::proposals::Proposal::Remove(prop) => {
                private_types::proposals::Proposal::Remove(
                    private_types::proposals::RemoveProposal::from_public_unchecked(prop),
                )
            }
            public_types::proposals::Proposal::PreSharedKey(prop) => {
                private_types::proposals::Proposal::PreSharedKey(
                    private_types::proposals::PreSharedKeyProposal::from_public_unchecked(prop),
                )
            }
            public_types::proposals::Proposal::ReInit(prop) => {
                private_types::proposals::Proposal::ReInit(
                    private_types::proposals::ReInitProposal::from_public_unchecked(prop),
                )
            }
            public_types::proposals::Proposal::ExternalInit(prop) => {
                private_types::proposals::Proposal::ExternalInit(
                    private_types::proposals::ExternalInitProposal::from_public_unchecked(prop),
                )
            }
            public_types::proposals::Proposal::GroupContextExtensions(prop) => {
                private_types::proposals::Proposal::GroupContextExtensions(
                    private_types::proposals::GroupContextExtensionProposal::from_public_unchecked(
                        prop,
                    ),
                )
            }
            public_types::proposals::Proposal::AppAck(prop) => {
                private_types::proposals::Proposal::AppAck(
                    private_types::proposals::AppAckProposal::from_public_unchecked(prop),
                )
            }
        }
    }
}

impl PrivateSpecType for private_types::proposals::AddProposal {
    type Public = public_types::proposals::AddProposal;
    fn from_public_unchecked(add_proposal: public_types::proposals::AddProposal) -> Self {
        Self {
            key_package: private_types::key_package::KeyPackage::from_public_unchecked(
                add_proposal.key_package,
            ),
        }
    }
}

impl PrivateSpecType for private_types::proposals::UpdateProposal {
    type Public = public_types::proposals::UpdateProposal;
    fn from_public_unchecked(update_proposal: public_types::proposals::UpdateProposal) -> Self {
        Self {
            leaf_node: private_types::tree::LeafNode::from_public_unchecked(
                update_proposal.leaf_node,
            ),
        }
    }
}

impl PrivateSpecType for private_types::proposals::RemoveProposal {
    type Public = public_types::proposals::RemoveProposal;
    fn from_public_unchecked(remove_proposal: public_types::proposals::RemoveProposal) -> Self {
        Self {
            removed: private_types::tree::LeafNodeIndex::from_public_unchecked(
                remove_proposal.removed,
            ),
        }
    }
}

impl PrivateSpecType for private_types::proposals::PreSharedKeyProposal {
    type Public = public_types::proposals::PreSharedKeyProposal;
    fn from_public_unchecked(psk_proposal: public_types::proposals::PreSharedKeyProposal) -> Self {
        Self {
            psk: private_types::psk::PreSharedKeyId::from_public_unchecked(psk_proposal.psk),
        }
    }
}

impl PrivateSpecType for private_types::proposals::ReInitProposal {
    type Public = public_types::proposals::ReInitProposal;
    fn from_public_unchecked(reinit_proposal: public_types::proposals::ReInitProposal) -> Self {
        Self {
            group_id: private_types::GroupId::from_public_unchecked(reinit_proposal.group_id),
            version: private_types::ProtocolVersion::from_public_unchecked(reinit_proposal.version),
            ciphersuite: private_types::Ciphersuite::from_public_unchecked(
                reinit_proposal.ciphersuite,
            ),
            extensions: private_types::extensions::Extensions::from_public_unchecked(
                reinit_proposal.extensions,
            ),
        }
    }
}

impl PrivateSpecType for private_types::proposals::ExternalInitProposal {
    type Public = public_types::proposals::ExternalInitProposal;
    fn from_public_unchecked(
        ex_init_proposal: public_types::proposals::ExternalInitProposal,
    ) -> Self {
        Self {
            kem_output: ex_init_proposal.kem_output.into(),
        }
    }
}

impl PrivateSpecType for private_types::proposals::AppAckProposal {
    type Public = public_types::proposals::AppAckProposal;
    fn from_public_unchecked(appack_proposal: public_types::proposals::AppAckProposal) -> Self {
        Self {
            received_ranges: appack_proposal
                .received_ranges
                .into_iter()
                .map(private_types::proposals::MessageRange::from_public_unchecked)
                .collect(),
        }
    }
}

impl PrivateSpecType for private_types::proposals::MessageRange {
    type Public = public_types::proposals::MessageRange;
    fn from_public_unchecked(msg_range: public_types::proposals::MessageRange) -> Self {
        Self {
            sender: private_types::key_package::KeyPackageRef::from_public_unchecked(
                msg_range.sender,
            ),
            first_generation: msg_range.first_generation,
            last_generation: msg_range.last_generation,
        }
    }
}

impl PrivateSpecType for private_types::proposals::Sender {
    type Public = public_types::proposals::Sender;
    fn from_public_unchecked(sender: public_types::proposals::Sender) -> Self {
        match sender {
            public_types::proposals::Sender::Member(leaf_node_index) => Self::Member(
                private_types::tree::LeafNodeIndex::from_public_unchecked(leaf_node_index),
            ),
            public_types::proposals::Sender::External(sender_ext_index) => Self::External(
                private_types::extensions::SenderExtensionIndex::from_public_unchecked(
                    sender_ext_index,
                ),
            ),
            public_types::proposals::Sender::NewMemberProposal => Self::NewMemberProposal,
            public_types::proposals::Sender::NewMemberCommit => Self::NewMemberCommit,
        }
    }
}

impl PrivateSpecType for private_types::proposals::GroupContextExtensionProposal {
    type Public = public_types::proposals::GroupContextExtensionProposal;
    fn from_public_unchecked(
        gce_proposal: public_types::proposals::GroupContextExtensionProposal,
    ) -> Self {
        Self {
            extensions: private_types::extensions::Extensions::from_public_unchecked(
                gce_proposal.extensions,
            ),
        }
    }
}

impl PrivateSpecType for private_types::proposals::ProposalRef {
    type Public = public_types::proposals::ProposalRef;
    fn from_public_unchecked(v: Self::Public) -> Self {
        Self(private_types::HashReference::from_public_unchecked(v.0))
    }
}

impl PrivateSpecType for private_types::proposals::ProposalOrRefType {
    type Public = public_types::proposals::ProposalOrRefType;
    fn from_public_unchecked(v: Self::Public) -> Self {
        match v {
            public_types::proposals::ProposalOrRefType::Proposal => {
                private_types::proposals::ProposalOrRefType::Proposal
            }
            public_types::proposals::ProposalOrRefType::Reference => {
                private_types::proposals::ProposalOrRefType::Reference
            }
        }
    }
}

impl PrivateSpecType for private_types::proprietary::queued_proposal::QueuedProposal {
    type Public = openmls_traits::storage::QueuedProposal;
    fn from_public_unchecked(v: Self::Public) -> Self {
        Self {
            proposal: private_types::proposals::Proposal::from_public_unchecked(v.proposal),
            proposal_reference: private_types::proposals::ProposalRef::from_public_unchecked(
                v.proposal_ref,
            ),
            sender: private_types::proposals::Sender::from_public_unchecked(v.sender),
            proposal_or_ref_type:
                private_types::proposals::ProposalOrRefType::from_public_unchecked(
                    v.proposal_or_ref_type,
                ),
        }
    }
}
