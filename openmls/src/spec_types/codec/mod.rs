mod proposals {
    use crate::spec_types::proposals::*;
    use std::io::Write;
    use tls_codec::{Error, Serialize, Size};

    impl Size for ProposalType {
        fn tls_serialized_len(&self) -> usize {
            2
        }
    }

    impl Serialize for ProposalType {
        fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
            writer.write_all(&u16::from(*self).to_be_bytes())?;

            Ok(2)
        }
    }

    impl From<u16> for ProposalType {
        fn from(value: u16) -> Self {
            match value {
                1 => ProposalType::Add,
                2 => ProposalType::Update,
                3 => ProposalType::Remove,
                4 => ProposalType::PreSharedKey,
                5 => ProposalType::Reinit,
                6 => ProposalType::ExternalInit,
                7 => ProposalType::GroupContextExtensions,
                8 => ProposalType::AppAck,
                unknown => ProposalType::Unknown(unknown),
            }
        }
    }

    impl From<ProposalType> for u16 {
        fn from(value: ProposalType) -> Self {
            match value {
                ProposalType::Add => 1,
                ProposalType::Update => 2,
                ProposalType::Remove => 3,
                ProposalType::PreSharedKey => 4,
                ProposalType::Reinit => 5,
                ProposalType::ExternalInit => 6,
                ProposalType::GroupContextExtensions => 7,
                ProposalType::AppAck => 8,
                ProposalType::Unknown(unknown) => unknown,
            }
        }
    }
}
