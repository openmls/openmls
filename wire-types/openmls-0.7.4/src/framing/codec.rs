use std::io::Read;
use tls_codec::{Deserialize, Size};

use crate::versions::ProtocolVersion;

use super::*;

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
