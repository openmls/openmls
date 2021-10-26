use std::mem::replace;

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::types::SignatureScheme;

pub struct Identity {
    pub(crate) kpb: KeyPackageBundle,
    pub(crate) credential: CredentialBundle,
}

impl Identity {
    pub(crate) fn new(ciphersuite: CiphersuiteName, crypto: &OpenMlsRustCrypto, id: &[u8]) -> Self {
        let credential_bundle = CredentialBundle::new(
            id.to_vec(),
            CredentialType::Basic,
            SignatureScheme::from(ciphersuite),
            crypto,
        )
        .unwrap();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &credential_bundle, crypto, vec![]).unwrap();
        Self {
            kpb: key_package_bundle,
            credential: credential_bundle,
        }
    }

    /// Update the key package bundle in this identity.
    /// The function returns the old `KeyPackageBundle`.
    pub fn update(&mut self, crypto: &OpenMlsRustCrypto) -> KeyPackageBundle {
        let ciphersuite = self.kpb.key_package().ciphersuite_name();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &self.credential, crypto, vec![]).unwrap();

        replace(&mut self.kpb, key_package_bundle)
    }

    /// Get the plain credential as byte vector.
    pub fn credential(&self) -> &[u8] {
        self.credential.credential().identity()
    }
}
