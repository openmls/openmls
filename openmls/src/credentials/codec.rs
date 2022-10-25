use std::io::Read;

use openmls_traits::types::SignatureScheme;
use tls_codec::{TlsByteVecU16, VLBytes};

use super::*;

// TODO(#1053): This is implemented manually because we throw a `DecodingError`
//              in all cases but `Credential::Basic`.
impl tls_codec::Deserialize for Credential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let val = u16::tls_deserialize(bytes)?;
        let credential_type = CredentialType::try_from(val)
            .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))?;
        match credential_type {
            CredentialType::Basic => {
                let basic = BasicCredential::tls_deserialize(bytes)?;

                Ok(Credential::Basic(basic))
            }
            _ => Err(tls_codec::Error::DecodingError(format!(
                "{:?} can not be deserialized.",
                credential_type
            ))),
        }
    }
}

// TODO(#1053): This is implemented manually because we call `SignaturePublicKey::new(...)`
//              and return a `DecodingError` in case when `SignaturePublicKey::new(...)` fails.
impl tls_codec::Deserialize for BasicCredential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let identity = TlsByteVecU16::tls_deserialize(bytes)?;
        let signature_scheme = SignatureScheme::tls_deserialize(bytes)?;
        let public_key_bytes = VLBytes::tls_deserialize(bytes)?;
        let public_key =
            SignaturePublicKey::new(public_key_bytes, signature_scheme).map_err(|e| {
                tls_codec::Error::DecodingError(format!(
                    "Error creating signature public key {:?}",
                    e
                ))
            })?;
        Ok(BasicCredential {
            identity,
            signature_scheme,
            public_key,
        })
    }
}
