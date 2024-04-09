use crate::spec_types as private_types;
use crate::spec_types::conversion::unchecked::PrivateSpecType;
use openmls_spec_types as public_types;

impl PrivateSpecType for private_types::psk::ResumptionPskUsage {
    type Public = public_types::psk::ResumptionPskUsage;
    fn from_public_unchecked(psk_usage: public_types::psk::ResumptionPskUsage) -> Self {
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

impl PrivateSpecType for private_types::psk::PreSharedKeyId {
    type Public = public_types::psk::PreSharedKeyId;
    fn from_public_unchecked(psk_id: public_types::psk::PreSharedKeyId) -> Self {
        match psk_id {
            public_types::psk::PreSharedKeyId::External(external_psk) => Self::External(
                private_types::psk::ExternalPsk::from_public_unchecked(external_psk),
            ),
            public_types::psk::PreSharedKeyId::Resumption(resumption_psk) => Self::Resumption(
                private_types::psk::ResumptionPsk::from_public_unchecked(resumption_psk),
            ),
        }
    }
}

impl PrivateSpecType for private_types::psk::ExternalPsk {
    type Public = public_types::psk::ExternalPsk;
    fn from_public_unchecked(external_psk: public_types::psk::ExternalPsk) -> Self {
        Self {
            psk_id: external_psk.psk_id.into(),
            psk_nonce: external_psk.psk_nonce.into(),
        }
    }
}

impl PrivateSpecType for private_types::psk::ResumptionPsk {
    type Public = public_types::psk::ResumptionPsk;
    fn from_public_unchecked(resumption_psk: public_types::psk::ResumptionPsk) -> Self {
        Self {
            usage: private_types::psk::ResumptionPskUsage::from_public_unchecked(
                resumption_psk.usage,
            ),
            psk_group_id: private_types::GroupId::from_public_unchecked(
                resumption_psk.psk_group_id,
            ),
            psk_epoch: private_types::GroupEpoch::from_public_unchecked(resumption_psk.psk_epoch),
            psk_nonce: resumption_psk.psk_nonce.into(),
        }
    }
}
