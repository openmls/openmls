use std::io::Read;
use tls_codec::{Deserialize, Size};

use crate::versions::ProtocolVersion;

use super::{
    mls_auth_content::FramedContentAuthData, mls_content_in::FramedContentBodyIn,
    private_message_in::PrivateMessageContentIn, *,
};

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
    // https://validation.openmls.tech/#valn1303
    if !padding.into_iter().all(|byte| byte == 0x00) {
        return Err(Error::InvalidInput);
    }

    Ok(PrivateMessageContentIn { content, auth })
}

impl Deserialize for MlsMessageIn {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let version = ProtocolVersion::tls_deserialize(bytes)?;
        let body = MlsMessageBodyIn::tls_deserialize(bytes)?;

        // This is required by the RFC in the struct definition of MLSMessage
        if version != ProtocolVersion::Mls10 {
            return Err(tls_codec::Error::DecodingError(
                "MlsMessage protocol version is not 1.0".into(),
            ));
        }

        // KeyPackage version must match MlsMessage version.
        // https://validation.openmls.tech/#valn0205
        if let MlsMessageBodyIn::KeyPackage(key_package) = &body {
            if !key_package.version_is_supported(version) {
                return Err(tls_codec::Error::DecodingError(
                    "KeyPackage protocol version does not match MlsMessage version.".into(),
                ));
            }
        }
        Ok(Self { version, body })
    }
}

impl DeserializeBytes for MlsMessageIn {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let message = MlsMessageIn::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[message.tls_serialized_len()..];
        Ok((message, remainder))
    }
}
