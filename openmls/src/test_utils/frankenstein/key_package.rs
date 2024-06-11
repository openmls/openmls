use std::ops::{Deref, DerefMut};

use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::{signatures::Signer, types::Ciphersuite, OpenMlsProvider};
use tls_codec::*;

use super::{extensions::FrankenExtension, leaf_node::FrankenLeafNode};
use crate::{
    ciphersuite::{
        signable::{Signable, SignedStruct},
        signature::{OpenMlsSignaturePublicKey, Signature},
    },
    credentials::{BasicCredential, CredentialWithKey},
    key_packages::{KeyPackage, KeyPackageIn},
    prelude::KeyPackageBundle,
    test_utils::OpenMlsRustCrypto,
    versions::ProtocolVersion,
};

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenKeyPackage {
    pub payload: FrankenKeyPackageTbs,
    pub signature: VLBytes,
}

impl FrankenKeyPackage {
    // Re-sign both the KeyPackage and the enclosed LeafNode
    pub fn resign(&mut self, signer: &impl Signer) {
        self.payload.leaf_node.resign(None, signer);
        let new_self = self.payload.clone().sign(signer).unwrap();
        let _ = std::mem::replace(self, new_self);
    }

    // Only re-sign the KeyPackage
    pub fn resign_only_key_package(&mut self, signer: &impl Signer) {
        let new_self = self.payload.clone().sign(signer).unwrap();
        let _ = std::mem::replace(self, new_self);
    }
}

impl Deref for FrankenKeyPackage {
    type Target = FrankenKeyPackageTbs;

    fn deref(&self) -> &Self::Target {
        &self.payload
    }
}

impl DerefMut for FrankenKeyPackage {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.payload
    }
}

impl SignedStruct<FrankenKeyPackageTbs> for FrankenKeyPackage {
    fn from_payload(payload: FrankenKeyPackageTbs, signature: Signature) -> Self {
        Self {
            payload,
            signature: signature.as_slice().to_owned().into(),
        }
    }
}

const SIGNATURE_KEY_PACKAGE_LABEL: &str = "KeyPackageTBS";

impl Signable for FrankenKeyPackageTbs {
    type SignedOutput = FrankenKeyPackage;

    fn unsigned_payload(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    fn label(&self) -> &str {
        SIGNATURE_KEY_PACKAGE_LABEL
    }
}

impl From<KeyPackage> for FrankenKeyPackage {
    fn from(kp: KeyPackage) -> Self {
        FrankenKeyPackage::tls_deserialize(&mut kp.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
    }
}

impl From<KeyPackageBundle> for FrankenKeyPackage {
    fn from(kp: KeyPackageBundle) -> Self {
        FrankenKeyPackage::tls_deserialize(
            &mut kp
                .key_package()
                .tls_serialize_detached()
                .unwrap()
                .as_slice(),
        )
        .unwrap()
    }
}

impl From<FrankenKeyPackage> for KeyPackage {
    fn from(fkp: FrankenKeyPackage) -> Self {
        KeyPackageIn::tls_deserialize(&mut fkp.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
            .into()
    }
}

impl From<FrankenKeyPackage> for KeyPackageIn {
    fn from(fkp: FrankenKeyPackage) -> Self {
        KeyPackageIn::tls_deserialize(&mut fkp.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
    }
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenKeyPackageTbs {
    pub protocol_version: u16,
    pub ciphersuite: u16,
    pub init_key: VLBytes,
    pub leaf_node: FrankenLeafNode,
    pub extensions: Vec<FrankenExtension>,
}

#[derive(
    Debug, Clone, PartialEq, Eq, TlsSerialize, TlsDeserialize, TlsDeserializeBytes, TlsSize,
)]
pub struct FrankenLifetime {
    pub not_before: u64,
    pub not_after: u64,
}

#[openmls_test]
fn test_franken_key_package() {
    let config = ciphersuite;

    let (credential, signer) = {
        let credential = BasicCredential::new(b"test identity".to_vec());
        let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
        signature_keys.store(provider.storage()).unwrap();

        (credential, signature_keys)
    };
    let signature_key = OpenMlsSignaturePublicKey::new(
        signer.to_public_vec().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_key.into(),
    };

    let kp = KeyPackage::builder()
        .build(config, provider, &signer, credential_with_key)
        .unwrap();

    let ser = kp.key_package().tls_serialize_detached().unwrap();
    let fkp = FrankenKeyPackage::tls_deserialize(&mut ser.as_slice()).unwrap();

    let ser2 = fkp.tls_serialize_detached().unwrap();
    assert_eq!(ser, ser2);

    let kp2 = KeyPackage::from(fkp.clone());
    assert_eq!(kp.key_package(), &kp2);
}
