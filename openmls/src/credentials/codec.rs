use std::io::Read;

use tls_codec::TlsByteVecU16;

use super::*;

impl tls_codec::Deserialize for BasicCredential {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let identity = TlsByteVecU16::tls_deserialize(bytes)?;
        let signature_scheme = SignatureScheme::tls_deserialize(bytes)?;
        let public_key_bytes = TlsByteVecU16::tls_deserialize(bytes)?;
        let public_key = SignaturePublicKey::new(public_key_bytes.into(), signature_scheme)
            .map_err(|e| {
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
