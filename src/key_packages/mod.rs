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

use crate::ciphersuite::{signable::*, *};
use crate::codec::*;
use crate::creds::*;
use crate::extensions::*;

mod codec;

mod test_key_packages;

// This implementation currently supports the following
pub(crate) const CIPHERSUITES: &[CiphersuiteName] = &[
    CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
];
pub(crate) const SUPPORTED_PROTOCOL_VERSIONS: &[ProtocolVersion] = &[CURRENT_PROTOCOL_VERSION];
pub(crate) const SUPPORTED_EXTENSIONS: &[ExtensionType] = &[ExtensionType::Lifetime];

#[derive(Debug, PartialEq, Clone)]
pub struct KeyPackage {
    protocol_version: ProtocolVersion,
    cipher_suite: Ciphersuite,
    hpke_init_key: HPKEPublicKey,
    credential: Credential,
    extensions: Vec<Extension>,
    signature: Signature,
}

impl KeyPackage {
    /// Create a new key package but only with the given `extensions` for the
    /// given `ciphersuite` and `identity`, and the initial HPKE key pair `init_key`.
    fn new(
        ciphersuite: Ciphersuite,
        hpke_init_key: &HPKEPublicKey,
        signature_key: &SignaturePrivateKey,
        credential: Credential,
        extensions: &[Extension],
    ) -> Self {
        //let credential = Credential::Basic(identity.into());
        let mut key_package = Self {
            protocol_version: CURRENT_PROTOCOL_VERSION,
            cipher_suite: ciphersuite,
            hpke_init_key: hpke_init_key.to_owned(),
            credential,
            extensions: extensions.to_vec(),
            signature: Signature::new_empty(),
        };
        let payload = &key_package.unsigned_payload().unwrap();

        key_package.signature = ciphersuite.sign(signature_key, payload).unwrap();
        key_package
    }

    /// Verify that the signature on this key package is valid.
    pub(crate) fn verify(&self) -> bool {
        self.credential
            .verify(&self.unsigned_payload().unwrap(), &self.signature)
    }

    /// Compute the hash of the encoding of this key package.
    pub(crate) fn hash(&self) -> Vec<u8> {
        let bytes = self.encode_detached().unwrap();
        self.cipher_suite.hash(&bytes)
    }

    /// Get the extension of `extension_type`.
    /// Returns `Some(extension)` if present and `None` if the extension is not present.
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

    /// Add (or replace) an extension to the KeyPackage.
    pub(crate) fn add_extension(&mut self, extension: Extension) {
        self.remove_extension(extension.extension_type);
        self.extensions.push(extension);
    }

    /// Remove an extension from the KeyPackage
    pub(crate) fn remove_extension(&mut self, extension_type: ExtensionType) {
        self.extensions
            .retain(|e| e.extension_type != extension_type);
    }

    /// Get a reference to the credential.
    pub(crate) fn get_credential(&self) -> &Credential {
        &self.credential
    }

    /// Get a reference to the HPKE init key.
    pub(crate) fn get_hpke_init_key(&self) -> &HPKEPublicKey {
        &self.hpke_init_key
    }

    /// Get a reference to the `Ciphersuite`.
    pub(crate) fn get_cipher_suite(&self) -> &Ciphersuite {
        &self.cipher_suite
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

#[derive(Debug, Clone)]
pub struct KeyPackageBundle {
    key_package: KeyPackage,
    private_key: HPKEPrivateKey,
}

impl KeyPackageBundle {
    /// Create a new `KeyPackageBundle` for the given `ciphersuite`, `identity`,
    /// and `extensions`.
    /// This generates a fresh HPKE key pair for this bundle.
    ///
    /// Returns a new `KeyPackageBundle`.
    pub fn new(
        ciphersuite: Ciphersuite,
        signature_key: &SignaturePrivateKey,
        credential: Credential,
        extensions: Option<Vec<Extension>>,
    ) -> Self {
        let keypair = ciphersuite.new_hpke_keypair();
        Self::new_with_keypair(
            &ciphersuite,
            signature_key,
            credential,
            extensions,
            &keypair,
        )
    }

    /// Create a new `KeyPackageBundle` for the given `ciphersuite`, `identity`,
    /// and `extensions`, using the given HPKE `key_pair`.
    ///
    /// Returns a new `KeyPackageBundle`.
    pub fn new_with_keypair(
        ciphersuite: &Ciphersuite,
        signature_key: &SignaturePrivateKey,
        credential: Credential,
        extensions: Option<Vec<Extension>>,
        key_pair: &HPKEKeyPair,
    ) -> Self {
        let capabilities_extension = CapabilitiesExtension::new(
            SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
            CIPHERSUITES.to_vec(),
            SUPPORTED_EXTENSIONS.to_vec(),
        );
        let mut final_extensions = vec![capabilities_extension.to_extension()];
        if let Some(mut extensions) = extensions {
            final_extensions.append(&mut extensions);
        }
        let key_package = KeyPackage::new(
            *ciphersuite,
            &key_pair.get_public_key(),
            signature_key,
            credential,
            &final_extensions,
        );
        KeyPackageBundle {
            key_package,
            private_key: key_pair.get_private_key().clone(),
        }
    }

    pub fn from_values(key_package: KeyPackage, private_key: HPKEPrivateKey) -> Self {
        Self {
            key_package,
            private_key,
        }
    }

    pub fn into_tuple(self) -> (HPKEPrivateKey, KeyPackage) {
        (self.private_key, self.key_package)
    }

    /// Get a reference to the `KeyPackage`.
    pub fn get_key_package(&self) -> &KeyPackage {
        &self.key_package
    }

    /// Get a reference to the `HPKEPrivateKey`.
    pub fn get_private_key(&self) -> &HPKEPrivateKey {
        &self.private_key
    }
}
