use tls_codec::{Deserialize, Serialize, Size};

use super::*;
use std::io::{Read, Write};

impl Deserialize for MlsPlaintext {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let content: MlsContent = MlsContent::tls_deserialize(bytes)?;
        let auth = deserialize_content_auth_data(bytes, content.body.content_type())?;
        let membership_tag = if content.sender.is_member() {
            Some(MembershipTag::tls_deserialize(bytes)?)
        } else {
            None
        };

        Ok(MlsPlaintext::new(content, auth, membership_tag))
    }
}

impl Size for MlsPlaintext {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.content.tls_serialized_len()
            + self.auth.tls_serialized_len()
            + if let Some(membership_tag) = &self.membership_tag {
                membership_tag.tls_serialized_len()
            } else {
                0
            }
    }
}

impl Serialize for MlsPlaintext {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.content.tls_serialize(writer)?;
        written += self.auth.tls_serialize(writer)?;
        written += if let Some(membership_tag) = &self.membership_tag {
            membership_tag.tls_serialize(writer)?
        } else {
            0
        };
        Ok(written)
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
        // Only members and new members joining via commit should have a context.
        debug_assert!(matches!(
            content.sender,
            Sender::Member(_) | Sender::NewMemberCommit
        ));
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

impl Serialize for MlsCiphertextContent {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut written = 0;

        // The `content` field is serialized without the `content_type`, which
        // is not part of the struct as per MLS spec.
        written += self.content.serialize_without_type(writer)?;

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
    let content = MlsContentBody::deserialize_without_type(bytes, content_type)?;
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
