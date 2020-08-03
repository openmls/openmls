// maelstrom
// Copyright (C) 2020 Raphael Robert
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see http://www.gnu.org/licenses/.

use crate::codec::*;
use crate::creds::*;
use crate::crypto::dh::*;
use crate::crypto::hash::*;
use crate::crypto::hpke::*;
use crate::crypto::signatures::*;
use crate::extensions::*;

#[derive(Debug, PartialEq, Clone)]
pub struct KeyPackage {
    pub protocol_version: ProtocolVersion,
    pub cipher_suite: CipherSuite,
    pub hpke_init_key: HPKEPublicKey,
    pub credential: Credential,
    pub extensions: Vec<Extension>,
    pub signature: Signature,
}

impl KeyPackage {
    pub fn new(ciphersuite: CipherSuite, init_key: &HPKEPublicKey, identity: &Identity) -> Self {
        let capabilities_extension = CapabilitiesExtension::new(
            vec![CURRENT_PROTOCOL_VERSION],
            vec![
                CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519,
                CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ],
            vec![ExtensionType::Lifetime],
        );
        let lifetime_extension = LifetimeExtension::new(LifetimeExtension::LIFETIME_4_WEEKS);
        let extensions = vec![
            capabilities_extension.to_extension(),
            lifetime_extension.to_extension(),
        ];
        KeyPackage::new_with_extensions(ciphersuite, init_key, identity, extensions)
    }
    pub fn new_with_extensions(
        ciphersuite: CipherSuite,
        hpke_init_key: &HPKEPublicKey,
        identity: &Identity,
        extensions: Vec<Extension>,
    ) -> Self {
        let credential = Credential::Basic(identity.into());
        let mut key_package = Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            cipher_suite: ciphersuite,
            hpke_init_key: hpke_init_key.to_owned(),
            credential,
            extensions,
            signature: Signature::new_empty(),
        };
        key_package.signature = identity.sign(&key_package.unsigned_payload().unwrap());
        key_package
    }
    pub fn self_verify(&self) -> bool {
        self.credential
            .verify(&self.unsigned_payload().unwrap(), &self.signature)
    }
    pub fn hash(&self) -> Vec<u8> {
        let bytes = self.encode_detached().unwrap();
        hash(HashAlgorithm::SHA256, &bytes)
    }
    pub fn has_extension(&self, extension_type: ExtensionType) -> bool {
        for e in &self.extensions {
            if e.get_type() == extension_type {
                return true;
            }
        }
        false
    }
    pub fn get_extension(&self, extension_type: ExtensionType) -> Option<ExtensionPayload> {
        for e in &self.extensions {
            if e.get_type() == extension_type {
                match extension_type {
                    ExtensionType::Capabilities => {
                        let capabilities_extension =
                            CapabilitiesExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::Capabilities(capabilities_extension));
                    }
                    ExtensionType::Lifetime => {
                        let lifetime_extension =
                            LifetimeExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::Lifetime(lifetime_extension));
                    }
                    ExtensionType::KeyID => {
                        let key_id_extension = KeyIDExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::KeyID(key_id_extension));
                    }
                    ExtensionType::ParentHash => {
                        let parent_hash_extension =
                            ParentHashExtension::new_from_bytes(&e.extension_data);
                        return Some(ExtensionPayload::ParentHash(parent_hash_extension));
                    }
                    _ => return None,
                }
            }
        }
        None
    }
}

impl Signable for KeyPackage {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut Vec::new();
        self.protocol_version.encode(buffer)?;
        self.cipher_suite.encode(buffer)?;
        self.hpke_init_key.encode(buffer)?;
        self.credential.encode(buffer)?;
        encode_vec(VecSize::VecU16, buffer, &self.extensions)?;
        Ok(buffer.to_vec())
    }
}

impl Codec for KeyPackage {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), CodecError> {
        buffer.append(&mut self.unsigned_payload()?);
        self.signature.encode(buffer)?;
        Ok(())
    }

    fn decode(cursor: &mut Cursor) -> Result<Self, CodecError> {
        // FIXME
        let protocol_version = ProtocolVersion::decode(cursor)?;
        let cipher_suite = CipherSuite::decode(cursor)?;
        let hpke_init_key = DHPublicKey::decode(cursor)?;
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
                        CapabilitiesExtension::new_from_bytes(&e.extension_data);
                    for v in capabilities_extension.versions.iter() {
                        if *v > CURRENT_PROTOCOL_VERSION {
                            return Err(CodecError::DecodingError);
                        }
                    }
                    if !capabilities_extension
                        .ciphersuites
                        .contains(&CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519)
                    {
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
                ExtensionType::Invalid => {}
                ExtensionType::Default => {}
            }
        }

        for _ in 0..kp.extensions.len() {}

        if !kp.self_verify() {
            return Err(CodecError::DecodingError);
        }
        Ok(kp)
    }
}

#[derive(Debug, Clone)]
pub struct KeyPackageBundle {
    pub key_package: KeyPackage,
    pub private_key: HPKEPrivateKey,
}

impl KeyPackageBundle {
    pub fn new(
        ciphersuite: CipherSuite,
        identity: &Identity,
        extensions_option: Option<Vec<Extension>>,
    ) -> Self {
        let keypair = HPKEKeyPair::new(ciphersuite.into()).unwrap();
        Self::new_with_keypair(ciphersuite, identity, extensions_option, &keypair)
    }
    pub fn new_with_keypair(
        ciphersuite: CipherSuite,
        identity: &Identity,
        extensions_option: Option<Vec<Extension>>,
        keypair: &HPKEKeyPair,
    ) -> Self {
        let private_key = keypair.private_key.clone();
        let capabilities_extension = CapabilitiesExtension::new(
            vec![CURRENT_PROTOCOL_VERSION],
            vec![
                CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519,
                CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
            ],
            vec![ExtensionType::Lifetime],
        );
        let mut final_extensions = vec![capabilities_extension.to_extension()];
        if let Some(mut extensions) = extensions_option {
            final_extensions.append(&mut extensions);
        }
        let key_package = KeyPackage::new_with_extensions(
            ciphersuite,
            &keypair.public_key,
            identity,
            final_extensions,
        );
        KeyPackageBundle {
            key_package,
            private_key,
        }
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

#[test]
fn generate_key_package() {
    let identity = Identity::new(
        CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
        vec![1, 2, 3],
    );
    let kp_bundle = KeyPackageBundle::new(
        CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
        &identity,
        None,
    );
    assert!(kp_bundle.key_package.self_verify());
}

#[test]
fn test_codec() {
    let ciphersuite = CipherSuite::MLS10_128_HPKEX25519_AES128GCM_SHA256_Ed25519;
    let identity = Identity::new(
        CipherSuite::MLS10_128_HPKEX25519_CHACHA20POLY1305_SHA256_Ed25519,
        vec![1, 2, 3],
    );
    let kpb = KeyPackageBundle::new(ciphersuite, &identity, None);
    let enc = kpb.encode_detached().unwrap();
    let kp = KeyPackage::decode(&mut Cursor::new(&enc)).unwrap();
    assert_eq!(kpb.key_package, kp);
}
