use crate::config::ProtocolVersion;
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
        let extensions = decode_vec(VecSize::VecU16, cursor)?;
        let signature = Signature::decode(cursor)?;
        let kp = KeyPackage {
            protocol_version,
            cipher_suite,
            hpke_init_key,
            credential,
            extensions,
            signature,
        };

        // TODO: check extensions

        let mut extensions = kp.extensions.clone();
        extensions.dedup();
        if kp.extensions.len() != extensions.len() {
            return Err(CodecError::DecodingError);
        }

        for e in extensions.iter() {
            match e.extension_type {
                ExtensionType::Capabilities => {
                    let capabilities_extension =
                        CapabilitiesExtension::new_from_bytes(&e.extension_data)?;
                    if !capabilities_extension.contains_ciphersuite(
                        &CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    ) {
                        return Err(CodecError::DecodingError);
                    }
                }
                ExtensionType::Lifetime => {
                    let lifetime_extension = LifetimeExtension::new_from_bytes(&e.extension_data);
                    if lifetime_extension.is_expired() {
                        return Err(CodecError::DecodingError);
                    }
                }
                ExtensionType::KeyID => {
                    let _key_id_extension = KeyIDExtension::new_from_bytes(&e.extension_data);
                }
                ExtensionType::ParentHash => {
                    let _parent_hash_extension =
                        ParentHashExtension::new_from_bytes(&e.extension_data);
                }
                ExtensionType::RatchetTree => {}
                ExtensionType::Reserved => {}
            }
        }

        for _ in 0..kp.extensions.len() {}

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
