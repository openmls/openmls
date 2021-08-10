use tls_codec::{Deserialize, Serialize, Size, TlsByteVecU16, TlsByteVecU32};

use super::*;
use std::io::{Read, Write};

impl<'a> tls_codec::Deserialize for VerifiableMlsPlaintext<'a> {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let group_id = GroupId::tls_deserialize(bytes)?;
        let epoch = GroupEpoch::tls_deserialize(bytes)?;
        let sender = Sender::tls_deserialize(bytes)?;
        let authenticated_data = TlsByteVecU32::tls_deserialize(bytes)?;
        let content_type = ContentType::tls_deserialize(bytes)?;
        let content = MlsPlaintextContentType::deserialize(content_type, bytes)?;
        let signature = Signature::tls_deserialize(bytes)?;
        let confirmation_tag = Option::<ConfirmationTag>::tls_deserialize(bytes)?;
        let membership_tag = Option::<MembershipTag>::tls_deserialize(bytes)?;

        let verifiable = VerifiableMlsPlaintext::new(
            MlsPlaintextTbs::new(
                None,
                group_id,
                epoch,
                sender,
                authenticated_data,
                content_type,
                content,
            ),
            signature,
            confirmation_tag,
            membership_tag,
        );

        Ok(verifiable)
    }
}

impl<'a> tls_codec::Size for VerifiableMlsPlaintext<'a> {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.tbs.group_id.tls_serialized_len()
            + self.tbs.epoch.tls_serialized_len()
            + self.tbs.sender.tls_serialized_len()
            + self.tbs.authenticated_data.tls_serialized_len()
            + self.tbs.content_type.tls_serialized_len()
            + self.tbs.payload.tls_serialized_len()
            + self.signature.tls_serialized_len()
            + self.confirmation_tag.tls_serialized_len()
            + self.membership_tag.tls_serialized_len()
    }
}

impl<'a> tls_codec::Serialize for VerifiableMlsPlaintext<'a> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.tbs.group_id.tls_serialize(writer)?;
        written += self.tbs.epoch.tls_serialize(writer)?;
        written += self.tbs.sender.tls_serialize(writer)?;
        written += self.tbs.authenticated_data.tls_serialize(writer)?;
        written += self.tbs.content_type.tls_serialize(writer)?;
        written += self.tbs.payload.tls_serialize(writer)?;
        written += self.signature.tls_serialize(writer)?;
        written += self.confirmation_tag.tls_serialize(writer)?;
        self.membership_tag
            .tls_serialize(writer)
            .map(|l| l + written)
    }
}

impl tls_codec::Size for MlsPlaintextContentType {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        match self {
            MlsPlaintextContentType::Application(application_data) => {
                application_data.tls_serialized_len()
            }
            MlsPlaintextContentType::Proposal(proposal) => proposal.tls_serialized_len(),
            MlsPlaintextContentType::Commit(commit) => commit.tls_serialized_len(),
        }
    }
}

impl tls_codec::Serialize for MlsPlaintextContentType {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            MlsPlaintextContentType::Application(application_data) => {
                let written = application_data.tls_serialize(writer)?;
                debug_assert_eq!(written, application_data.tls_serialized_len());
                Ok(written)
            }
            MlsPlaintextContentType::Proposal(proposal) => {
                let written = proposal.tls_serialize(writer)?;
                debug_assert_eq!(written, proposal.tls_serialized_len());
                Ok(written)
            }
            MlsPlaintextContentType::Commit(commit) => {
                let written = commit.tls_serialize(writer)?;
                debug_assert_eq!(written, commit.tls_serialized_len());
                Ok(written)
            }
        }
    }
}

impl MlsPlaintextContentType {
    fn deserialize<R: Read>(
        content_type: ContentType,
        bytes: &mut R,
    ) -> Result<Self, tls_codec::Error> {
        match content_type {
            ContentType::Application => {
                let application_data = TlsByteVecU32::tls_deserialize(bytes)?;
                Ok(MlsPlaintextContentType::Application(application_data))
            }
            ContentType::Proposal => {
                let proposal = Proposal::tls_deserialize(bytes)?;
                Ok(MlsPlaintextContentType::Proposal(proposal))
            }
            ContentType::Commit => {
                let commit = Commit::tls_deserialize(bytes)?;
                Ok(MlsPlaintextContentType::Commit(commit))
            }
        }
    }
}

pub(super) fn serialize_plaintext_tbs<'a, W: Write>(
    serialized_context: impl Into<Option<&'a [u8]>>,
    group_id: &GroupId,
    epoch: &GroupEpoch,
    sender: &Sender,
    authenticated_data: &TlsByteVecU32,
    content_type: &ContentType,
    payload: &MlsPlaintextContent,
    buffer: &mut W,
) -> Result<usize, tls_codec::Error> {
    let mut written = if let Some(serialized_context) = serialized_context.into() {
        buffer.write(serialized_context)?
    } else {
        0
    };
    written += group_id.tls_serialize(buffer)?;
    written += epoch.tls_serialize(buffer)?;
    written += sender.tls_serialize(buffer)?;
    written += authenticated_data.tls_serialize(buffer)?;
    written += content_type.tls_serialize(buffer)?;
    payload.tls_serialize(buffer).map(|l| l + written)
}

impl<'a> tls_codec::Size for MlsPlaintextTbs<'a> {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        let context_len = if let Some(serialized_context) = self.serialized_context {
            serialized_context.len()
        } else {
            0
        };
        context_len
            + self.group_id.tls_serialized_len()
            + self.epoch.tls_serialized_len()
            + self.sender.tls_serialized_len()
            + self.authenticated_data.tls_serialized_len()
            + self.content_type.tls_serialized_len()
            + self.payload.tls_serialized_len()
    }
}

impl<'a> tls_codec::Serialize for MlsPlaintextTbs<'a> {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        serialize_plaintext_tbs(
            self.serialized_context,
            &self.group_id,
            &self.epoch,
            &self.sender,
            &self.authenticated_data,
            &self.content_type,
            &self.payload,
            writer,
        )
    }
}

impl MlsCiphertextContent {
    pub(crate) fn deserialize<R: Read>(
        content_type: ContentType,
        bytes: &mut R,
    ) -> Result<Self, tls_codec::Error> {
        let content = match content_type {
            MlsPlaintextContentType::Application => {
                let application_data = TlsByteVecU32::tls_deserialize(bytes)?;
                MlsPlaintextContent::Application(application_data)
            }
            MlsPlaintextContentType::Proposal => {
                let proposal = Proposal::tls_deserialize(bytes)?;
                MlsPlaintextContent::Proposal(proposal)
            }
            MlsPlaintextContentType::Commit => {
                let commit = Commit::tls_deserialize(bytes)?;
                MlsPlaintextContent::Commit(commit)
            }
        };
        let signature = Signature::tls_deserialize(bytes)?;
        let confirmation_tag = Option::<ConfirmationTag>::tls_deserialize(bytes)?;
        let padding = TlsByteVecU16::tls_deserialize(bytes)?;
        Ok(MlsCiphertextContent {
            content,
            signature,
            confirmation_tag,
            padding,
        })
    }
}
