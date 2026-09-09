use std::io::{Read, Write};

use tls_codec::*;

use super::{
    extensions::{
        FrankenApplicationIdExtension, FrankenExtension, FrankenExtensionType,
        FrankenExternalPubExtension, FrankenExternalSendersExtension, FrankenRatchetTreeExtension,
        FrankenRequiredCapabilitiesExtension,
    },
    FrankenAddProposal, FrankenCustomProposal, FrankenExternalInitProposal,
    FrankenPreSharedKeyProposal, FrankenProposal, FrankenProposalType, FrankenReInitProposal,
    FrankenRemoveProposal, FrankenUpdateProposal,
};

#[cfg(feature = "extensions-draft")]
use super::{FrankenAppDataUpdateProposal, FrankenAppEphemeralProposal};

fn vlbytes_len_len(length: usize) -> usize {
    if length <= 0x3f {
        1
    } else if length <= 0x3fff {
        2
    } else if length <= 0x3fff_ffff {
        4
    } else {
        8
    }
}

impl Size for FrankenProposalType {
    fn tls_serialized_len(&self) -> usize {
        2
    }
}

impl Deserialize for FrankenProposalType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut proposal_type = [0u8; 2];
        bytes.read_exact(&mut proposal_type)?;

        Ok(FrankenProposalType::from(u16::from_be_bytes(proposal_type)))
    }
}

impl Serialize for FrankenProposalType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&u16::from(*self).to_be_bytes())?;

        Ok(2)
    }
}

impl DeserializeBytes for FrankenProposalType {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let proposal_type = FrankenProposalType::tls_deserialize(&mut bytes_ref)?;
        Ok((proposal_type, bytes_ref))
    }
}

impl Size for FrankenProposal {
    fn tls_serialized_len(&self) -> usize {
        self.proposal_type().tls_serialized_len()
            + match self {
                FrankenProposal::Add(p) => p.tls_serialized_len(),
                FrankenProposal::Update(p) => p.tls_serialized_len(),
                FrankenProposal::Remove(p) => p.tls_serialized_len(),
                FrankenProposal::PreSharedKey(p) => p.tls_serialized_len(),
                FrankenProposal::ReInit(p) => p.tls_serialized_len(),
                FrankenProposal::ExternalInit(p) => p.tls_serialized_len(),
                FrankenProposal::GroupContextExtensions(p) => p.tls_serialized_len(),
                #[cfg(feature = "extensions-draft")]
                FrankenProposal::AppEphemeral(p) => p.tls_serialized_len(),
                #[cfg(feature = "extensions-draft")]
                FrankenProposal::AppDataUpdate(p) => p.tls_serialized_len(),
                // Only the payload is written; the proposal type is already
                // accounted for above.
                FrankenProposal::Custom(p) => p.payload.tls_serialized_len(),
            }
    }
}

impl Serialize for FrankenProposal {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.proposal_type().tls_serialize(writer)?;
        match self {
            FrankenProposal::Add(p) => p.tls_serialize(writer),
            FrankenProposal::Update(p) => p.tls_serialize(writer),
            FrankenProposal::Remove(p) => p.tls_serialize(writer),
            FrankenProposal::PreSharedKey(p) => p.tls_serialize(writer),
            FrankenProposal::ReInit(p) => p.tls_serialize(writer),
            FrankenProposal::ExternalInit(p) => p.tls_serialize(writer),
            FrankenProposal::GroupContextExtensions(p) => p.tls_serialize(writer),
            #[cfg(feature = "extensions-draft")]
            FrankenProposal::AppEphemeral(p) => p.tls_serialize(writer),
            #[cfg(feature = "extensions-draft")]
            FrankenProposal::AppDataUpdate(p) => p.tls_serialize(writer),
            FrankenProposal::Custom(p) => p.payload.tls_serialize(writer),
        }
        .map(|l| written + l)
    }
}

impl Deserialize for FrankenProposal {
    fn tls_deserialize<R: std::io::Read>(bytes: &mut R) -> Result<Self, tls_codec::Error>
    where
        Self: Sized,
    {
        let proposal_type = FrankenProposalType::tls_deserialize(bytes)?;
        let proposal = match proposal_type {
            FrankenProposalType::Add => {
                FrankenProposal::Add(FrankenAddProposal::tls_deserialize(bytes)?)
            }
            FrankenProposalType::Update => {
                FrankenProposal::Update(FrankenUpdateProposal::tls_deserialize(bytes)?)
            }
            FrankenProposalType::Remove => {
                FrankenProposal::Remove(FrankenRemoveProposal::tls_deserialize(bytes)?)
            }
            FrankenProposalType::PreSharedKey => {
                FrankenProposal::PreSharedKey(FrankenPreSharedKeyProposal::tls_deserialize(bytes)?)
            }
            FrankenProposalType::Reinit => {
                FrankenProposal::ReInit(FrankenReInitProposal::tls_deserialize(bytes)?)
            }
            FrankenProposalType::ExternalInit => {
                FrankenProposal::ExternalInit(FrankenExternalInitProposal::tls_deserialize(bytes)?)
            }
            FrankenProposalType::GroupContextExtensions => FrankenProposal::GroupContextExtensions(
                Vec::<FrankenExtension>::tls_deserialize(bytes)?,
            ),
            #[cfg(feature = "extensions-draft")]
            FrankenProposalType::AppEphemeral => {
                FrankenProposal::AppEphemeral(FrankenAppEphemeralProposal::tls_deserialize(bytes)?)
            }
            #[cfg(feature = "extensions-draft")]
            FrankenProposalType::AppDataUpdate => FrankenProposal::AppDataUpdate(
                FrankenAppDataUpdateProposal::tls_deserialize(bytes)?,
            ),
            FrankenProposalType::Custom(_) => {
                let payload = VLBytes::tls_deserialize(bytes)?;
                let custom_proposal = FrankenCustomProposal {
                    proposal_type: proposal_type.into(),
                    payload,
                };
                FrankenProposal::Custom(custom_proposal)
            }
        };
        Ok(proposal)
    }
}

impl DeserializeBytes for FrankenProposal {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let proposal = FrankenProposal::tls_deserialize(&mut bytes_ref)?;
        Ok((proposal, bytes_ref))
    }
}

impl Size for FrankenExtensionType {
    fn tls_serialized_len(&self) -> usize {
        2
    }
}

impl Deserialize for FrankenExtensionType {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut extension_type = [0u8; 2];
        bytes.read_exact(&mut extension_type)?;

        Ok(FrankenExtensionType::from(u16::from_be_bytes(
            extension_type,
        )))
    }
}

impl DeserializeBytes for FrankenExtensionType {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let extension_type = FrankenExtensionType::tls_deserialize(&mut bytes_ref)?;
        Ok((extension_type, bytes_ref))
    }
}

impl Serialize for FrankenExtensionType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(&u16::from(*self).to_be_bytes())?;

        Ok(2)
    }
}

impl Size for FrankenExtension {
    fn tls_serialized_len(&self) -> usize {
        let extension_type_length = 2;
        let extension_data_len = match self {
            FrankenExtension::ApplicationId(e) => e.tls_serialized_len(),
            FrankenExtension::RatchetTree(e) => e.tls_serialized_len(),
            FrankenExtension::RequiredCapabilities(e) => e.tls_serialized_len(),
            FrankenExtension::ExternalPub(e) => e.tls_serialized_len(),
            FrankenExtension::ExternalSenders(e) => e.tls_serialized_len(),
            FrankenExtension::LastResort => 0,
            FrankenExtension::Unknown(_, e) => e.as_slice().len(),
        };
        let vlbytes_len_len = vlbytes_len_len(extension_data_len);
        extension_type_length + vlbytes_len_len + extension_data_len
    }
}

impl Serialize for FrankenExtension {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let written = self.extension_type().tls_serialize(writer)?;

        // subtract the two bytes for the type header
        let extension_data_len = self.tls_serialized_len() - 2;
        let mut extension_data = Vec::with_capacity(extension_data_len);

        let _ = match self {
            FrankenExtension::ApplicationId(e) => e.tls_serialize(&mut extension_data),
            FrankenExtension::RatchetTree(e) => e.tls_serialize(&mut extension_data),
            FrankenExtension::RequiredCapabilities(e) => e.tls_serialize(&mut extension_data),
            FrankenExtension::ExternalPub(e) => e.tls_serialize(&mut extension_data),
            FrankenExtension::ExternalSenders(e) => e.tls_serialize(&mut extension_data),
            FrankenExtension::LastResort => Ok(0),
            FrankenExtension::Unknown(_, e) => extension_data
                .write_all(e.as_slice())
                .map(|_| e.as_slice().len())
                .map_err(|_| tls_codec::Error::EndOfStream),
        }?;

        Serialize::tls_serialize(&extension_data, writer).map(|l| l + written)
    }
}

impl Deserialize for FrankenExtension {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // Read the extension type and extension data.
        let extension_type = FrankenExtensionType::tls_deserialize(bytes)?;
        let extension_data = VLBytes::tls_deserialize(bytes)?;

        // Now deserialize the extension itself from the extension data.
        let mut extension_data = extension_data.as_slice();
        Ok(match extension_type {
            FrankenExtensionType::ApplicationId => FrankenExtension::ApplicationId(
                FrankenApplicationIdExtension::tls_deserialize(&mut extension_data)?,
            ),
            FrankenExtensionType::RatchetTree => FrankenExtension::RatchetTree(
                FrankenRatchetTreeExtension::tls_deserialize(&mut extension_data)?,
            ),
            FrankenExtensionType::RequiredCapabilities => FrankenExtension::RequiredCapabilities(
                FrankenRequiredCapabilitiesExtension::tls_deserialize(&mut extension_data)?,
            ),
            FrankenExtensionType::ExternalPub => FrankenExtension::ExternalPub(
                FrankenExternalPubExtension::tls_deserialize(&mut extension_data)?,
            ),
            FrankenExtensionType::ExternalSenders => FrankenExtension::ExternalSenders(
                FrankenExternalSendersExtension::tls_deserialize(&mut extension_data)?,
            ),
            FrankenExtensionType::LastResort => FrankenExtension::LastResort,
            FrankenExtensionType::Unknown(unknown) => {
                FrankenExtension::Unknown(unknown, extension_data.to_vec().into())
            }
        })
    }
}

impl DeserializeBytes for FrankenExtension {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), tls_codec::Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let extension = FrankenExtension::tls_deserialize(&mut bytes_ref)?;
        Ok((extension, bytes_ref))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::frankenstein::{
        FrankenCommit, FrankenCustomProposal, FrankenExternalPsk, FrankenPreSharedKeyId,
        FrankenPreSharedKeyProposal, FrankenProposalOrRef, FrankenPsk, FrankenReInitProposal,
        FrankenRemoveProposal,
    };

    #[cfg(feature = "extensions-draft")]
    use crate::messages::proposals::AppDataUpdateOperation;

    /// Proposals that can be built without a key package or a leaf node.
    fn proposals() -> Vec<FrankenProposal> {
        let proposals = vec![
            FrankenProposal::Remove(FrankenRemoveProposal { removed: 3 }),
            FrankenProposal::PreSharedKey(FrankenPreSharedKeyProposal {
                psk: FrankenPreSharedKeyId {
                    psk: FrankenPsk::External(FrankenExternalPsk {
                        psk_id: vec![7, 8].into(),
                    }),
                    psk_nonce: vec![9; 32].into(),
                },
            }),
            FrankenProposal::ReInit(FrankenReInitProposal {
                group_id: vec![1, 2, 3].into(),
                version: 1,
                ciphersuite: 1,
                extensions: vec![FrankenExtension::LastResort],
            }),
            FrankenProposal::ExternalInit(FrankenExternalInitProposal {
                kem_output: vec![4; 32].into(),
            }),
            FrankenProposal::GroupContextExtensions(vec![FrankenExtension::Unknown(
                0xf042,
                vec![5, 6].into(),
            )]),
            FrankenProposal::Custom(FrankenCustomProposal {
                proposal_type: 0xf001,
                payload: vec![1, 2, 3, 4].into(),
            }),
        ];

        #[cfg(feature = "extensions-draft")]
        let proposals = {
            let mut proposals = proposals;
            proposals.push(FrankenProposal::AppEphemeral(FrankenAppEphemeralProposal {
                component_id: 0x8001,
                data: vec![1, 2, 3].into(),
            }));
            proposals.push(FrankenProposal::AppDataUpdate(
                FrankenAppDataUpdateProposal {
                    component_id: 0x8001,
                    operation: AppDataUpdateOperation::Update(vec![4, 5, 6].into()),
                },
            ));
            proposals
        };

        proposals
    }

    #[test]
    fn proposal_length_matches_serialization() {
        for proposal in proposals() {
            let serialized = proposal.tls_serialize_detached().unwrap();
            assert_eq!(
                proposal.tls_serialized_len(),
                serialized.len(),
                "wrong length for {proposal:?}"
            );
            assert_eq!(
                FrankenProposal::tls_deserialize_exact(&serialized).unwrap(),
                proposal
            );
        }
    }

    /// A wrong length breaks any enclosing struct that writes a length prefix,
    /// so exercise a proposal nested in a commit as well.
    #[test]
    fn commit_with_a_custom_proposal_round_trips() {
        let commit = FrankenCommit {
            proposals: vec![FrankenProposalOrRef::Proposal(FrankenProposal::Custom(
                FrankenCustomProposal {
                    proposal_type: 0xf001,
                    payload: vec![1, 2, 3, 4].into(),
                },
            ))],
            path: None,
        };

        let serialized = commit.tls_serialize_detached().unwrap();
        assert_eq!(
            FrankenCommit::tls_deserialize_exact(&serialized).unwrap(),
            commit
        );
    }
}
