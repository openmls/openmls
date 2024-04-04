use crate::spec_types as private_types;
use openmls_spec_types as public_types;

impl private_types::proposals::ProposalType {
    pub(in crate::spec_types) fn from_public(
        proposal_type: public_types::proposals::ProposalType,
    ) -> Self {
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

impl private_types::proposals::Proposal {
    pub(in crate::spec_types) fn from_public(proposal: public_types::proposals::Proposal) -> Self {
        match proposal {
            public_types::proposals::Proposal::Add(prop) => {
                private_types::proposals::Proposal::Add(
                    private_types::proposals::AddProposal::from_public(prop),
                )
            }
            public_types::proposals::Proposal::Update(prop) => {
                private_types::proposals::Proposal::Update(
                    private_types::proposals::UpdateProposal::from_public(prop),
                )
            }
            public_types::proposals::Proposal::Remove(prop) => {
                private_types::proposals::Proposal::Remove(
                    private_types::proposals::RemoveProposal::from_public(prop),
                )
            }
            public_types::proposals::Proposal::PreSharedKey(prop) => {
                private_types::proposals::Proposal::PreSharedKey(
                    private_types::proposals::PreSharedKeyProposal::from_public(prop),
                )
            }
            public_types::proposals::Proposal::ReInit(prop) => {
                private_types::proposals::Proposal::ReInit(
                    private_types::proposals::ReInitProposal::from_public(prop),
                )
            }
            public_types::proposals::Proposal::ExternalInit(prop) => {
                private_types::proposals::Proposal::ExternalInit(
                    private_types::proposals::ExternalInitProposal::from_public(prop),
                )
            }
            public_types::proposals::Proposal::GroupContextExtensions(prop) => {
                private_types::proposals::Proposal::GroupContextExtensions(
                    private_types::proposals::GroupContextExtensionProposal::from_public(prop),
                )
            }
            public_types::proposals::Proposal::AppAck(prop) => {
                private_types::proposals::Proposal::AppAck(
                    private_types::proposals::AppAckProposal::from_public(prop),
                )
            }
        }
    }
}

impl private_types::proposals::AddProposal {
    pub(in crate::spec_types) fn from_public(
        add_proposal: public_types::proposals::AddProposal,
    ) -> Self {
        Self {
            key_package: private_types::key_package::KeyPackage::from_public(
                add_proposal.key_package,
            ),
        }
    }
}

impl private_types::proposals::UpdateProposal {
    pub(in crate::spec_types) fn from_public(
        update_proposal: public_types::proposals::UpdateProposal,
    ) -> Self {
        Self {
            leaf_node: private_types::tree::LeafNode::from_public(update_proposal.leaf_node),
        }
    }
}

impl private_types::proposals::RemoveProposal {
    pub(in crate::spec_types) fn from_public(
        remove_proposal: public_types::proposals::RemoveProposal,
    ) -> Self {
        Self {
            removed: private_types::tree::LeafNodeIndex::from_public(remove_proposal.removed),
        }
    }
}

impl private_types::proposals::PreSharedKeyProposal {
    pub(in crate::spec_types) fn from_public(
        psk_proposal: public_types::proposals::PreSharedKeyProposal,
    ) -> Self {
        Self {
            psk: private_types::psk::PreSharedKeyId::from_public(psk_proposal.psk),
        }
    }
}

impl private_types::proposals::ReInitProposal {
    pub(in crate::spec_types) fn from_public(
        reinit_proposal: public_types::proposals::ReInitProposal,
    ) -> Self {
        Self {
            group_id: private_types::GroupId::from_public(reinit_proposal.group_id),
            version: private_types::ProtocolVersion::from_public(reinit_proposal.version),
            ciphersuite: private_types::Ciphersuite::from_public(reinit_proposal.ciphersuite),
            extensions: private_types::extensions::Extensions::from_public(
                reinit_proposal.extensions,
            ),
        }
    }
}

impl private_types::proposals::ExternalInitProposal {
    pub(in crate::spec_types) fn from_public(
        ex_init_proposal: public_types::proposals::ExternalInitProposal,
    ) -> Self {
        Self {
            kem_output: ex_init_proposal.kem_output.into(),
        }
    }
}

impl private_types::proposals::AppAckProposal {
    pub(in crate::spec_types) fn from_public(
        appack_proposal: public_types::proposals::AppAckProposal,
    ) -> Self {
        Self {
            received_ranges: appack_proposal
                .received_ranges
                .into_iter()
                .map(private_types::proposals::MessageRange::from_public)
                .collect(),
        }
    }
}

impl private_types::proposals::MessageRange {
    pub(in crate::spec_types) fn from_public(
        msg_range: public_types::proposals::MessageRange,
    ) -> Self {
        Self {
            sender: private_types::key_package::KeyPackageRef::from_public(msg_range.sender),
            first_generation: msg_range.first_generation,
            last_generation: msg_range.last_generation,
        }
    }
}

impl private_types::proposals::Sender {
    pub(in crate::spec_types) fn from_public(sender: public_types::proposals::Sender) -> Self {
        match sender {
            public_types::proposals::Sender::Member(leaf_node_index) => Self::Member(
                private_types::tree::LeafNodeIndex::from_public(leaf_node_index),
            ),
            public_types::proposals::Sender::External(sender_ext_index) => Self::External(
                private_types::extensions::SenderExtensionIndex::from_public(sender_ext_index),
            ),
            public_types::proposals::Sender::NewMemberProposal => Self::NewMemberProposal,
            public_types::proposals::Sender::NewMemberCommit => Self::NewMemberCommit,
        }
    }
}

impl private_types::proposals::GroupContextExtensionProposal {
    pub(in crate::spec_types) fn from_public(
        gce_proposal: public_types::proposals::GroupContextExtensionProposal,
    ) -> Self {
        Self {
            extensions: private_types::extensions::Extensions::from_public(gce_proposal.extensions),
        }
    }
}
