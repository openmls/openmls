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
        // TODO: The following should replace the code chunk below. Needs further
        //       investigation.
        // let extensions = Extension::new_vec_from_cursor(cursor)?;
        // First parse the extension bytes into the `ExtensionStruct`.
        let extension_struct_vec: Vec<ExtensionStruct> = decode_vec(VecSize::VecU16, cursor)?;

        // Now create the result vector of `Extension`s.
        let mut extensions: Vec<Box<dyn Extension>> = Vec::new();
        for extension in extension_struct_vec.iter() {
            // Make sure there are no duplicate extensions.
            if extensions
                .iter()
                .find(|e| e.get_type() == extension.get_extension_type())
                .is_some()
            {
                return Err(CodecError::DecodingError);
            }
            let bytes = extension.get_extension_data();
            let ext = match extension.get_extension_type() {
                ExtensionType::Capabilities => CapabilitiesExtension::new_from_bytes(bytes),
                ExtensionType::KeyID => KeyIDExtension::new_from_bytes(bytes),
                ExtensionType::Lifetime => LifetimeExtension::new_from_bytes(bytes),
                ExtensionType::ParentHash => ParentHashExtension::new_from_bytes(bytes),
                ExtensionType::RatchetTree => RatchetTreeExtension::new_from_bytes(bytes),
                _ => Err(ExtensionError::InvalidExtensionType.into()),
            }?;
            extensions.push(ext);
        }
        // ===
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
