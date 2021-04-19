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
        println!("Decoded ProtocolVersion");
        let cipher_suite_name = CiphersuiteName::decode(cursor)?;
        println!("Decoded CiphersutieName");
        let hpke_init_key = HPKEPublicKey::decode(cursor)?;
        println!("Decoded HPKE PK");
        let credential = Credential::decode(cursor)?;
        println!("Decoded Credential");
        let extensions = extensions_vec_from_cursor(cursor)?;
        println!("Decoded Extensions");
        let signature = Signature::decode(cursor)?;
        println!("Decoded Signature");
        let kp = KeyPackage {
            protocol_version,
            ciphersuite: Config::ciphersuite(cipher_suite_name)?,
            hpke_init_key,
            credential,
            extensions,
            signature,
        };

        if kp.verify().is_err() {
            log::error!("Error verifying a key package after decoding\n{:?}", kp);
            return Err(CodecError::DecodingError);
        }
        Ok(kp)
    }
}
