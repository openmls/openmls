use crate::spec_types as private_types;
use openmls_spec_types as public_types;

impl private_types::psk::ResumptionPskUsage {
    pub(in crate::spec_types) fn from_public(
        psk_usage: public_types::psk::ResumptionPskUsage,
    ) -> Self {
        match psk_usage {
            public_types::psk::ResumptionPskUsage::Application => {
                private_types::psk::ResumptionPskUsage::Application
            }
            public_types::psk::ResumptionPskUsage::Reinit => {
                private_types::psk::ResumptionPskUsage::Reinit
            }
            public_types::psk::ResumptionPskUsage::Branch => {
                private_types::psk::ResumptionPskUsage::Branch
            }
        }
    }
}

impl private_types::psk::PreSharedKeyId {
    pub(in crate::spec_types) fn from_public(psk_id: public_types::psk::PreSharedKeyId) -> Self {
        match psk_id {
            public_types::psk::PreSharedKeyId::External(external_psk) => {
                Self::External(private_types::psk::ExternalPsk::from_public(external_psk))
            }
            public_types::psk::PreSharedKeyId::Resumption(resumption_psk) => Self::Resumption(
                private_types::psk::ResumptionPsk::from_public(resumption_psk),
            ),
        }
    }
}

impl private_types::psk::ExternalPsk {
    pub(in crate::spec_types) fn from_public(external_psk: public_types::psk::ExternalPsk) -> Self {
        Self {
            psk_id: external_psk.psk_id.into(),
            psk_nonce: external_psk.psk_nonce.into(),
        }
    }
}

impl private_types::psk::ResumptionPsk {
    pub(in crate::spec_types) fn from_public(
        resumption_psk: public_types::psk::ResumptionPsk,
    ) -> Self {
        Self {
            usage: private_types::psk::ResumptionPskUsage::from_public(resumption_psk.usage),
            psk_group_id: private_types::GroupId::from_public(resumption_psk.psk_group_id),
            psk_epoch: private_types::GroupEpoch::from_public(resumption_psk.psk_epoch),
            psk_nonce: resumption_psk.psk_nonce.into(),
        }
    }
}
