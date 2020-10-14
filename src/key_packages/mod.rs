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
use crate::config::ProtocolVersion;
use crate::creds::*;
use crate::extensions::{CapabilitiesExtension, Extension, ExtensionStruct, ExtensionType};

mod codec;

mod test_key_packages;

#[derive(Debug, Clone, PartialEq)]
pub struct KeyPackage {
    protocol_version: ProtocolVersion,
    cipher_suite: Ciphersuite,
    hpke_init_key: HPKEPublicKey,
    credential: Credential,
    extensions: Vec<Box<dyn Extension>>,
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
        extensions: Vec<Box<dyn Extension>>,
    ) -> Self {
        let mut key_package = Self {
            // TODO: #85 Take from global config.
            protocol_version: ProtocolVersion::default(),
            cipher_suite: ciphersuite,
            hpke_init_key: hpke_init_key.to_owned(),
            credential,
            extensions,
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

    /// Get a reference to the extension of `extension_type`.
    /// Returns `Some(extension)` if present and `None` if the extension is not present.
    pub(crate) fn get_extension(
        &self,
        extension_type: ExtensionType,
    ) -> Option<&Box<dyn Extension>> {
        for e in &self.extensions {
            if e.get_type() == extension_type {
                return Some(e);
            }
        }
        None
    }

    /// Add (or replace) an extension to the KeyPackage.
    pub(crate) fn add_extension(&mut self, extension: Box<dyn Extension>) {
        self.remove_extension(extension.get_type());
        self.extensions.push(extension);
    }

    /// Remove an extension from the KeyPackage
    pub(crate) fn remove_extension(&mut self, extension_type: ExtensionType) {
        self.extensions.retain(|e| e.get_type() != extension_type);
    }

    /// Get a reference to the credential.
    pub(crate) fn get_credential(&self) -> &Credential {
        &self.credential
    }

    /// Get a reference to the HPKE init key.
    pub(crate) fn get_hpke_init_key(&self) -> &HPKEPublicKey {
        &self.hpke_init_key
    }

    /// Set a new HPKE init key.
    pub(crate) fn set_hpke_init_key(&mut self, hpke_init_key: HPKEPublicKey) {
        self.hpke_init_key = hpke_init_key;
    }

    /// Get a reference to the `Ciphersuite`.
    pub(crate) fn get_cipher_suite(&self) -> &Ciphersuite {
        &self.cipher_suite
    }

    /// Get a reference to the extensions of this key package.
    pub fn get_extensions_ref(&self) -> &[Box<dyn Extension>] {
        &self.extensions
    }
}

impl Signable for KeyPackage {
    fn unsigned_payload(&self) -> Result<Vec<u8>, CodecError> {
        let buffer = &mut Vec::new();
        self.protocol_version.encode(buffer)?;
        self.cipher_suite.encode(buffer)?;
        self.hpke_init_key.encode(buffer)?;
        self.credential.encode(buffer)?;
        // Get extensions encoded. We need to build a Vec::<ExtensionStruct> first.
        let encoded_extensions: Vec<ExtensionStruct> = self
            .extensions
            .iter()
            .map(|e| e.to_extension_struct())
            .collect();
        encode_vec(VecSize::VecU16, buffer, &encoded_extensions)?;
        Ok(buffer.to_vec())
    }
}

#[derive(Debug, Clone)]
pub struct KeyPackageBundle {
    pub(crate) key_package: KeyPackage,
    pub(crate) private_key: HPKEPrivateKey,
}

impl KeyPackageBundle {
    /// Create a new `KeyPackageBundle` for the given `ciphersuite`, `identity`,
    /// and `extensions`. Note that the capabilities extension gets added
    /// automatically, based on the configuration.
    /// This generates a fresh HPKE key pair for this bundle.
    ///
    /// Returns a new `KeyPackageBundle`.
    pub fn new(
        ciphersuite: &Ciphersuite,
        signature_key: &SignaturePrivateKey,
        credential: Credential, // FIXME: must be reference
        extensions: Option<Vec<Box<dyn Extension>>>,
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
        extensions: Option<Vec<Box<dyn Extension>>>,
        key_pair: &HPKEKeyPair,
    ) -> Self {
        // TODO: #85 this must be configurable.
        let mut final_extensions: Vec<Box<dyn Extension>> =
            vec![Box::new(CapabilitiesExtension::default())];
        if let Some(mut extensions) = extensions {
            final_extensions.append(&mut extensions);
        }
        let key_package = KeyPackage::new(
            *ciphersuite,
            &key_pair.get_public_key(),
            signature_key,
            credential,
            final_extensions,
        );
        KeyPackageBundle {
            key_package,
            private_key: key_pair.get_private_key(),
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
