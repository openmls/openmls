use std::io::Read;

use tls_codec::{Deserialize, DeserializeBytes, Error, Serialize, Size};

use super::*;

impl Size for Credential {
    #[inline]
    fn tls_serialized_len(&self) -> usize {
        self.credential_type.tls_serialized_len()
            + match &self.credential {
                MlsCredentialType::Basic(c) => c.tls_serialized_len(),
                MlsCredentialType::X509(_) => unimplemented!(),
            }
    }
}

impl Serialize for Credential {
    fn tls_serialize<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, Error> {
        match &self.credential {
            MlsCredentialType::Basic(basic_credential) => {
                let written = CredentialType::Basic.tls_serialize(writer)?;
                basic_credential.tls_serialize(writer).map(|l| l + written)
            }
            // TODO #134: implement encoding for X509 certificates
            MlsCredentialType::X509(_) => Err(Error::EncodingError(
                "X509 certificates are not yet implemented.".to_string(),
            )),
        }
    }
}

impl Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, Error> {
        let val = u16::tls_deserialize(bytes)?;
        let credential_type = CredentialType::from(val);
        match credential_type {
            CredentialType::Basic => Ok(Credential::from(MlsCredentialType::Basic(
                BasicCredential::tls_deserialize(bytes)?,
            ))),
            _ => Err(Error::DecodingError(format!(
                "{credential_type:?} can not be deserialized."
            ))),
        }
    }
}

impl DeserializeBytes for Credential {
    fn tls_deserialize_bytes(bytes: &[u8]) -> Result<(Self, &[u8]), Error>
    where
        Self: Sized,
    {
        let mut bytes_ref = bytes;
        let credential = Credential::tls_deserialize(&mut bytes_ref)?;
        let remainder = &bytes[credential.tls_serialized_len()..];
        Ok((credential, remainder))
    }
}
