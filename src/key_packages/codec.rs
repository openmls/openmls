use crate::config::{Config, ProtocolVersion};
use crate::extensions::*;
use crate::key_packages::*;

impl Codec for KeyPackage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let protocol_version = ProtocolVersion::decode(cursor)?;
        let cipher_suite_name = CiphersuiteName::decode(cursor)?;
        let hpke_init_key = HPKEPublicKey::decode(cursor)?;
        let credential = Credential::decode(cursor)?;
        let extensions = extensions_vec_from_cursor(cursor)?;
        let signature = Signature::decode(cursor)?;
        let kp = KeyPackage {
            protocol_version,
            ciphersuite: Config::ciphersuite(cipher_suite_name)?,
            hpke_init_key,
            credential,
            extensions,
            signature,
        };

        // TODO: #93 check extensions
        // for _ in 0..kp.extensions.len() {}

        if kp.verify().is_err() {
            return Err(CodecError::DecodingError);
        }
        Ok(kp)
    }
}
