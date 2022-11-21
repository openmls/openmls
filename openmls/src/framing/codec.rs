use tls_codec::{Deserialize, Serialize, Size, TlsByteVecU32, TlsByteVecU8};

use super::*;
use std::io::{Read, Write};

impl Deserialize for VerifiableMlsAuthContent {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let content: MlsContent = MlsContent::tls_deserialize(bytes)?;
        let auth = deserialize_content_auth_data(bytes, content.body.content_type())?;
        let membership_tag = Option::<MembershipTag>::tls_deserialize(bytes)?;

        // ValSem001: Check the wire format
        if wire_format != WireFormat::MlsPlaintext {
            return Err(tls_codec::Error::DecodingError(
                "Wrong wire format.".to_string(),
            ));
        }

        let verifiable = VerifiableMlsAuthContent::new(
            MlsContentTbs::new(
                wire_format,
                content.group_id,
                content.epoch,
                content.sender,
                content.authenticated_data,
                content.body,
            ),
            auth,
            membership_tag,
        );

        Ok(verifiable)
    }
}

impl Size for VerifiableMlsAuthContent {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.tbs.wire_format.tls_serialized_len()
            + self.tbs.content.tls_serialized_len()
            + self.auth.tls_serialized_len()
            + self.membership_tag.tls_serialized_len()
    }
}

impl Serialize for VerifiableMlsAuthContent {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.tbs.wire_format.tls_serialize(writer)?;
        written += self.tbs.content.tls_serialize(writer)?;
        written += self.auth.tls_serialize(writer)?;
        self.membership_tag
            .tls_serialize(writer)
            .map(|l| l + written)
    }
}

pub(super) fn serialize_plaintext_tbs<'a, W: Write>(
    wire_format: WireFormat,
    content: &MlsContent,
    serialized_context: impl Into<Option<&'a [u8]>>,
    buffer: &mut W,
) -> Result<usize, tls_codec::Error> {
    let mut written = wire_format.tls_serialize(buffer)?;
    written += content.tls_serialize(buffer)?;
    written += if let Some(serialized_context) = serialized_context.into() {
        // Only a member should have a context.
        debug_assert!(matches!(content.sender, Sender::Member(_)));
        buffer.write(serialized_context)?
    } else {
        0
    };
    Ok(written)
}

impl Size for MlsContentTbs {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.wire_format.tls_serialized_len()
            + self.content.tls_serialized_len()
            + if let Some(serialized_context) = &self.serialized_context {
                serialized_context.tls_serialized_len()
            } else {
                0
            }
    }
}

impl Serialize for MlsContentTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        serialize_plaintext_tbs(
            self.wire_format,
            &self.content,
            self.serialized_context.as_deref(),
            writer,
        )
    }
}

impl Size for MlsContentAuthData {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.signature.tls_serialized_len()
            + if let Some(confirmation_tag) = &self.confirmation_tag {
                confirmation_tag.tls_serialized_len()
            } else {
                0
            }
    }
}

impl Serialize for MlsContentAuthData {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.signature.tls_serialize(writer)?;
        written += if let Some(confirmation_tag) = &self.confirmation_tag {
            confirmation_tag.tls_serialize(writer)?
        } else {
            0
        };
        Ok(written)
    }
}

fn deserialize_content_auth_data<R: Read>(
    bytes: &mut R,
    content_type: ContentType,
) -> Result<MlsContentAuthData, tls_codec::Error> {
    let signature = Signature::tls_deserialize(bytes)?;
    let confirmation_tag = if matches!(content_type, ContentType::Commit) {
        Some(ConfirmationTag::tls_deserialize(bytes)?)
    } else {
        None
    };
    Ok(MlsContentAuthData {
        signature,
        confirmation_tag,
    })
}

impl Deserialize for MlsCiphertext {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let group_id = GroupId::tls_deserialize(bytes)?;
        let epoch = GroupEpoch::tls_deserialize(bytes)?;
        let content_type = ContentType::tls_deserialize(bytes)?;
        let authenticated_data = VLBytes::tls_deserialize(bytes)?;
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

// TODO(#1053): Replace with `derive(TlsSerialize)`.
impl Serialize for MlsMessage {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self.body {
            MlsMessageBody::Ciphertext(ref m) => m.tls_serialize(writer),
            MlsMessageBody::Plaintext(ref m) => m.tls_serialize(writer),
        }
    }
}

// TODO(#1053): Replace with `derive(TlsDeserialize)`.
impl Deserialize for MlsMessage {
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
                let body = match wire_format {
                    WireFormat::MlsPlaintext => {
                        let plaintext = VerifiableMlsAuthContent::tls_deserialize(&mut chain)?;
                        MlsMessageBody::Plaintext(plaintext)
                    }
                    WireFormat::MlsCiphertext => {
                        let ciphertext = MlsCiphertext::tls_deserialize(&mut chain)?;
                        MlsMessageBody::Ciphertext(ciphertext)
                    }
                };

                Ok(MlsMessage { body })
            }
            None => Err(tls_codec::Error::EndOfStream),
        }
    }
}

// TODO(#1053): Replace with `derive(Size)`.
impl Size for MlsMessage {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        match &self.body {
            MlsMessageBody::Plaintext(plaintext) => {
                VerifiableMlsAuthContent::tls_serialized_len(plaintext)
            }
            MlsMessageBody::Ciphertext(ciphertext) => MlsCiphertext::tls_serialized_len(ciphertext),
        }
    }
}

impl Size for MlsCiphertextContent {
    fn tls_serialized_len(&self) -> usize {
        self.content.tls_serialized_len() +
           self.auth.tls_serialized_len() +
            // Note: The padding is appended as a "raw" all-zero byte slice
            // with length `length_of_padding`. Thus, we only need to add
            // this length here.
            self.length_of_padding
    }
}

/// Serializes the content without the `content_type` field.
pub(super) fn serialize_content<W: Write>(
    content_body: &MlsContentBody,
    writer: &mut W,
) -> Result<usize, Error> {
    match content_body {
        MlsContentBody::Application(a) => a.tls_serialize(writer),
        MlsContentBody::Proposal(p) => p.tls_serialize(writer),
        MlsContentBody::Commit(c) => c.tls_serialize(writer),
    }
}

impl Serialize for MlsCiphertextContent {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut written = 0;

        // The `content` field is serialized without the `content_type`, which
        // is not part of the struct as per MLS spec.
        written += serialize_content(&self.content, writer)?;

        written += self.auth.tls_serialize(writer)?;
        let padding = vec![0u8; self.length_of_padding];
        writer.write_all(&padding)?;
        written += self.length_of_padding;

        Ok(written)
    }
}

/// This function implements deserialization manually, as it requires `content_type` as additional input.
pub(super) fn deserialize_ciphertext_content<R: Read>(
    bytes: &mut R,
    content_type: ContentType,
) -> Result<MlsCiphertextContent, tls_codec::Error> {
    let content = match content_type {
        ContentType::Application => {
            MlsContentBody::Application(TlsByteVecU32::tls_deserialize(bytes)?)
        }
        ContentType::Proposal => MlsContentBody::Proposal(Proposal::tls_deserialize(bytes)?),
        ContentType::Commit => MlsContentBody::Commit(Commit::tls_deserialize(bytes)?),
    };
    let auth = deserialize_content_auth_data(bytes, content_type)?;

    let padding = {
        let mut buffer = Vec::new();
        bytes
            .read_to_end(&mut buffer)
            .map_err(|_| Error::InvalidInput)?;
        buffer
    };

    let length_of_padding = padding.len();

    // ValSem011: MLSCiphertextContent padding must be all-zero.
    if !padding.into_iter().all(|byte| byte == 0x00) {
        return Err(Error::InvalidInput);
    }

    Ok(MlsCiphertextContent {
        content,
        auth,
        length_of_padding,
    })
}
