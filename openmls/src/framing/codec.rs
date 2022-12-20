use tls_codec::{Serialize, Size};

use super::{
    mls_auth_content::MlsContentAuthData,
    mls_content::{ContentType, MlsContentBody},
    *,
};
use std::io::{Read, Write};

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
    let auth = MlsContentAuthData::deserialize(bytes, content_type)?;

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
