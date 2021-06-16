use crate::config::{Config, ProtocolVersion};
use crate::extensions::*;
use crate::key_packages::*;

impl Codec for KeyPackage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.extend_from_slice(&self.encoded);
        self.signature.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let protocol_version = ProtocolVersion::decode(cursor)?;
        let cipher_suite_name = CiphersuiteName::decode(cursor)?;
        let hpke_init_key = HpkePublicKey::decode(cursor)?;
        let credential = Credential::decode(cursor)?;
        let extensions = extensions_vec_from_cursor(cursor)?;
        let signature = Signature::decode(cursor)?;
        let payload = KeyPackagePayload {
            protocol_version,
            ciphersuite: Config::ciphersuite(cipher_suite_name)?,
            hpke_init_key,
            credential,
            extensions,
        };
        let encoded = payload.unsigned_payload()?;
        let kp = KeyPackage {
            payload,
            signature,
            encoded,
        };

        if kp.verify().is_err() {
            log::error!("Error verifying a key package after decoding\n{:?}", kp);
            return Err(CodecError::DecodingError);
        }
        Ok(kp)
    }
}

impl tls_codec::TlsSize for KeyPackage {
    #[inline]
    fn serialized_len(&self) -> usize {
        self.encoded.len() + self.signature.serialized_len()
    }
}
