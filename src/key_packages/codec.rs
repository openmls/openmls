use crate::codec::{decode_vec, VecSize};
use crate::config::ProtocolVersion;
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
        let cipher_suite = Ciphersuite::decode(cursor)?;
        let hpke_init_key = HPKEPublicKey::decode(cursor)?;
        let credential = Credential::decode(cursor)?;
        let extensions = extensions_vec_from_cursor(cursor)?;
        let signature = Signature::decode(cursor)?;
        let kp = KeyPackage {
            protocol_version,
            cipher_suite,
            hpke_init_key,
            credential,
            extensions,
            signature,
        };

        // TODO: #93 check extensions
        // for _ in 0..kp.extensions.len() {}

        if !kp.verify() {
            return Err(CodecError::DecodingError);
        }
        Ok(kp)
    }
}

impl Codec for KeyPackageBundle {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        self.key_package.encode(buffer)?;
        self.private_key.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        let key_package = KeyPackage::decode(cursor)?;
        let private_key = HPKEPrivateKey::decode(cursor)?;
        Ok(KeyPackageBundle {
            key_package,
            private_key,
        })
    }
}
