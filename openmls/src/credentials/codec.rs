use std::io::Read;

use super::*;

impl tls_codec::Size for Credential {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.credential_type.tls_serialized_len()
            + match &self.credential {
                MlsCredentialType::Basic(c) => c.tls_serialized_len(),
                MlsCredentialType::X509(_) => unimplemented!(),
            }
    }
}

impl tls_codec::Serialize for Credential {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => {
                let written = CredentialType::Basic.tls_serialize(writer)?;
                basic_credential.tls_serialize(writer).map(|l| l + written)
            }
            // TODO #134: implement encoding for X509 certificates
            MlsCredentialType::X509(_) => Err(tls_codec::Error::EncodingError(
                "X509 certificates are not yet implemented.".to_string(),
            )),
        }
    }
}

impl tls_codec::Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let val = u16::tls_deserialize(bytes)?;
        let credential_type = CredentialType::try_from(val)
            .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))?;
        match credential_type {
            CredentialType::Basic => Ok(Credential::from(MlsCredentialType::Basic(
                BasicCredential::tls_deserialize(bytes)?,
            ))),
            _ => Err(tls_codec::Error::DecodingError(format!(
                "{:?} can not be deserialized.",
                credential_type
            ))),
        }
    }
}
