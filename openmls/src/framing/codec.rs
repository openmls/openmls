use std::io::{Read, Write};
use tls_codec::{Deserialize, Serialize, Size};

use crate::versions::ProtocolVersion;

use super::{
    mls_auth_content::FramedContentAuthData, mls_content_in::FramedContentBodyIn,
    private_message_in::PrivateMessageContentIn, *,
};

impl Size for PrivateMessageContent {
    fn tls_serialized_len(&self) -> usize {
        self.content.tls_serialized_len() +
           self.auth.tls_serialized_len() +
            // Note: The padding is appended as a "raw" all-zero byte slice
            // with length `length_of_padding`. Thus, we only need to add
            // this length here.
            self.length_of_padding
    }
}

impl Serialize for PrivateMessageContent {
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
) -> Result<PrivateMessageContentIn, tls_codec::Error> {
    let content = FramedContentBodyIn::deserialize_without_type(bytes, content_type)?;
    let auth = FramedContentAuthData::deserialize(bytes, content_type)?;

    let padding = {
        let mut buffer = Vec::new();
        bytes
            .read_to_end(&mut buffer)
            .map_err(|_| Error::InvalidInput)?;
        buffer
    };

    // ValSem011: PrivateMessageContentIn padding must be all-zero.
    if !padding.into_iter().all(|byte| byte == 0x00) {
        return Err(Error::InvalidInput);
    }

    Ok(PrivateMessageContentIn { content, auth })
}

impl Deserialize for MlsMessageIn {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let version = ProtocolVersion::tls_deserialize(bytes)?;
        let body = MlsMessageInBody::tls_deserialize(bytes)?;

        // KeyPackage version must match MlsMessage version.
        if let MlsMessageInBody::KeyPackage(key_package) = &body {
            if !key_package.version_is_supported(version) {
                return Err(tls_codec::Error::DecodingError(
                    "KeyPackage version does not match MlsMessage version.".into(),
                ));
            }
        }
        Ok(Self { version, body })
    }
}
