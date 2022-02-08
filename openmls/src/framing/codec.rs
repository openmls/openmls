use tls_codec::{Deserialize, Serialize, Size, TlsByteVecU16, TlsByteVecU32, TlsByteVecU8};

use super::*;
use std::io::{Read, Write};

impl tls_codec::Deserialize for VerifiableMlsPlaintext {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let group_id = GroupId::tls_deserialize(bytes)?;
        let epoch = GroupEpoch::tls_deserialize(bytes)?;
        let sender = Sender::tls_deserialize(bytes)?;
        let authenticated_data = TlsByteVecU32::tls_deserialize(bytes)?;
        let content_type = ContentType::tls_deserialize(bytes)?;
        let payload = MlsPlaintextContentType::deserialize(content_type, bytes)?;
        let signature = Signature::tls_deserialize(bytes)?;
        let confirmation_tag = Option::<ConfirmationTag>::tls_deserialize(bytes)?;
        let membership_tag = Option::<MembershipTag>::tls_deserialize(bytes)?;

        // ValSem001: Check the wire format
        if wire_format != WireFormat::MlsPlaintext {
            return Err(tls_codec::Error::DecodingError(
                "Wrong wire format.".to_string(),
            ));
        }

        let verifiable = VerifiableMlsPlaintext::new(
            MlsPlaintextTbs::new(
                wire_format,
                group_id,
                epoch,
                sender,
                authenticated_data,
                Payload {
                    payload,
                    content_type,
                },
            ),
            signature,
            confirmation_tag,
            membership_tag,
        );

        Ok(verifiable)
    }
}

impl tls_codec::Size for VerifiableMlsPlaintext {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.tbs.wire_format.tls_serialized_len()
            + self.tbs.group_id.tls_serialized_len()
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

impl tls_codec::Serialize for VerifiableMlsPlaintext {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.tbs.wire_format.tls_serialize(writer)?;
        written += self.tbs.group_id.tls_serialize(writer)?;
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

// This might get refactored with the TLS codec refactoring, just suppressing the warning for now
#[allow(clippy::too_many_arguments)]
pub(super) fn serialize_plaintext_tbs<'a, W: Write>(
    serialized_context: impl Into<Option<&'a [u8]>>,
    wire_format: WireFormat,
    group_id: &GroupId,
    epoch: &GroupEpoch,
    sender: &Sender,
    authenticated_data: &TlsByteVecU32,
    content_type: &ContentType,
    payload: &MlsPlaintextContentType,
    buffer: &mut W,
) -> Result<usize, tls_codec::Error> {
    let mut written = if let Some(serialized_context) = serialized_context.into() {
        // Only a member should have a context.
        debug_assert!(matches!(sender, Sender::Member(_)));
        buffer.write(serialized_context)?
    } else {
        0
    };
    written += wire_format.tls_serialize(buffer)?;
    written += group_id.tls_serialize(buffer)?;
    written += epoch.tls_serialize(buffer)?;
    written += sender.tls_serialize(buffer)?;
    written += authenticated_data.tls_serialize(buffer)?;
    written += content_type.tls_serialize(buffer)?;
    payload.tls_serialize(buffer).map(|l| l + written)
}

impl tls_codec::Size for MlsPlaintextTbs {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        let context_len = if let Some(serialized_context) = &self.serialized_context {
            serialized_context.len()
        } else {
            0
        };
        context_len
            + self.wire_format.tls_serialized_len()
            + self.group_id.tls_serialized_len()
            + self.epoch.tls_serialized_len()
            + self.sender.tls_serialized_len()
            + self.authenticated_data.tls_serialized_len()
            + self.content_type.tls_serialized_len()
            + self.payload.tls_serialized_len()
    }
}

impl tls_codec::Serialize for MlsPlaintextTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        serialize_plaintext_tbs(
            self.serialized_context.as_deref(),
            self.wire_format,
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

impl tls_codec::Deserialize for MlsCiphertext {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let group_id = GroupId::tls_deserialize(bytes)?;
        let epoch = GroupEpoch::tls_deserialize(bytes)?;
        let content_type = ContentType::tls_deserialize(bytes)?;
        let authenticated_data = TlsByteVecU32::tls_deserialize(bytes)?;
        let encrypted_sender_data = TlsByteVecU8::tls_deserialize(bytes)?;
        let ciphertext = TlsByteVecU32::tls_deserialize(bytes)?;

        // ValSem001: Check the wire format
        if wire_format != WireFormat::MlsCiphertext {
            return Err(tls_codec::Error::DecodingError(
                "Wrong wire format.".to_string(),
            ));
        }

        let mls_ciphertext = MlsCiphertext::new(
            wire_format,
            group_id,
            epoch,
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        );

        Ok(mls_ciphertext)
    }
}

impl MlsCiphertextContent {
    pub(crate) fn deserialize<R: Read>(
        content_type: ContentType,
        bytes: &mut R,
    ) -> Result<Self, tls_codec::Error> {
        let content = match content_type {
            ContentType::Application => {
                let application_data = TlsByteVecU32::tls_deserialize(bytes)?;
                MlsPlaintextContentType::Application(application_data)
            }
            ContentType::Proposal => {
                let proposal = Proposal::tls_deserialize(bytes)?;
                MlsPlaintextContentType::Proposal(proposal)
            }
            ContentType::Commit => {
                let commit = Commit::tls_deserialize(bytes)?;
                MlsPlaintextContentType::Commit(commit)
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

impl tls_codec::Serialize for MlsMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            MlsMessage::Ciphertext(m) => m.tls_serialize(writer),
            MlsMessage::Plaintext(m) => m.tls_serialize(writer),
        }
    }
}

impl tls_codec::Deserialize for MlsMessage {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        // Determine the wire format by looking at the first byte
        let mut first_byte_buffer = [0u8];
        bytes
            .read_exact(&mut first_byte_buffer)
            .map_err(|_| tls_codec::Error::EndOfStream)?;
        match first_byte_buffer.first() {
            Some(first_byte) => {
                let mut chain = first_byte_buffer.chain(bytes);
                let wire_format = WireFormat::tls_deserialize(&mut vec![*first_byte].as_slice())?;
                match wire_format {
                    WireFormat::MlsPlaintext => {
                        let plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut chain)?;
                        Ok(MlsMessage::Plaintext(Box::new(plaintext)))
                    }
                    WireFormat::MlsCiphertext => {
                        let ciphertext = MlsCiphertext::tls_deserialize(&mut chain)?;
                        Ok(MlsMessage::Ciphertext(Box::new(ciphertext)))
                    }
                }
            }
            None => Err(tls_codec::Error::EndOfStream),
        }
    }
}

impl tls_codec::Size for MlsMessage {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        match &self {
            MlsMessage::Plaintext(plaintext) => {
                VerifiableMlsPlaintext::tls_serialized_len(plaintext)
            }
            MlsMessage::Ciphertext(ciphertext) => MlsCiphertext::tls_serialized_len(ciphertext),
        }
    }
}
