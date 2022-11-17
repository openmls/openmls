use tls_codec::{Deserialize, Serialize, Size, TlsByteVecU32, TlsByteVecU8};

use super::*;
use std::io::{Read, Write};

impl Deserialize for VerifiableMlsPlaintext {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let wire_format = WireFormat::tls_deserialize(bytes)?;
        let content: MlsContent = MlsContent::tls_deserialize(bytes)?;
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
            MlsContentTbs::new(
                wire_format,
                content.group_id,
                content.epoch,
                content.sender,
                content.authenticated_data,
                content.body,
            ),
            signature,
            confirmation_tag,
            membership_tag,
        );

        Ok(verifiable)
    }
}

impl Size for VerifiableMlsPlaintext {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.tbs.wire_format.tls_serialized_len()
            + self.tbs.group_id.tls_serialized_len()
            + self.tbs.epoch.tls_serialized_len()
            + self.tbs.sender.tls_serialized_len()
            + self.tbs.authenticated_data.tls_serialized_len()
            + self.tbs.body.tls_serialized_len()
            + self.signature.tls_serialized_len()
            + self.confirmation_tag.tls_serialized_len()
            + self.membership_tag.tls_serialized_len()
    }
}

impl Serialize for VerifiableMlsPlaintext {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.tbs.wire_format.tls_serialize(writer)?;
        written += self.tbs.group_id.tls_serialize(writer)?;
        written += self.tbs.epoch.tls_serialize(writer)?;
        written += self.tbs.sender.tls_serialize(writer)?;
        written += self.tbs.authenticated_data.tls_serialize(writer)?;
        written += self.tbs.body.tls_serialize(writer)?;
        written += self.signature.tls_serialize(writer)?;
        written += self.confirmation_tag.tls_serialize(writer)?;
        self.membership_tag
            .tls_serialize(writer)
            .map(|l| l + written)
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
    payload: &MlsContentBody,
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
    payload.tls_serialize(buffer).map(|l| l + written)
}

impl Size for MlsContentTbs {
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
            + self.body.tls_serialized_len()
    }
}

impl Serialize for MlsContentTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        serialize_plaintext_tbs(
            self.serialized_context.as_deref(),
            self.wire_format,
            &self.group_id,
            &self.epoch,
            &self.sender,
            &self.authenticated_data,
            &self.body,
            writer,
        )
    }
}

impl Deserialize for MlsCiphertext {
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
                        let plaintext = VerifiableMlsPlaintext::tls_deserialize(&mut chain)?;
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
                VerifiableMlsPlaintext::tls_serialized_len(plaintext)
            }
            MlsMessageBody::Ciphertext(ciphertext) => MlsCiphertext::tls_serialized_len(ciphertext),
        }
    }
}

impl Size for MlsCiphertextContent {
    fn tls_serialized_len(&self) -> usize {
        self.content.tls_serialized_len() +
           self.signature.tls_serialized_len() +
            self.confirmation_tag.tls_serialized_len() +
            // Note: The padding is appended as a "raw" all-zero byte slice
            // with length `length_of_padding`. Thus, we only need to add
            // this length here.
            self.length_of_padding
    }
}

impl Serialize for MlsCiphertextContent {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut written = 0;

        written += self.content.tls_serialize(writer)?;
        written += self.signature.tls_serialize(writer)?;
        written += self.confirmation_tag.tls_serialize(writer)?;
        let padding = vec![0u8; self.length_of_padding];
        writer.write_all(&padding)?;
        written += self.length_of_padding;

        Ok(written)
    }
}

impl Deserialize for MlsCiphertextContent {
    /// We first decode `content`, `signature`, and `confirmation_tag`, and then make sure
    /// that the rest of the slice contains only zero bytes, i.e., is the padding.
    /// Note: This always "terminates" the `Read` instance because we call `read_to_end`.
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let content = MlsContentBody::tls_deserialize(bytes)?;
        let signature = Signature::tls_deserialize(bytes)?;
        let confirmation_tag = Option::<ConfirmationTag>::tls_deserialize(bytes)?;

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
            signature,
            confirmation_tag,
            length_of_padding,
        })
    }
}
