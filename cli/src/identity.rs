use std::mem::replace;

use openmls::prelude::*;

pub struct Identity {
    pub(crate) kpb: KeyPackageBundle,
    pub(crate) credential: Box<dyn CredentialBundle>,
}

impl Identity {
    pub(crate) fn new(ciphersuite: CiphersuiteName, id: &[u8]) -> Self {
        let credential_bundle =
            BasicCredentialBundle::new(id.to_vec(), SignatureScheme::from(ciphersuite)).unwrap();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &credential_bundle, vec![]).unwrap();
        Self {
            kpb: key_package_bundle,
            credential: Box::new(credential_bundle),
        }
    }

    /// Update the key package bundle in this identity.
    /// The function returns the old `KeyPackageBundle`.
    pub fn update(&mut self) -> KeyPackageBundle {
        let ciphersuite = self.kpb.key_package().ciphersuite_name();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &*self.credential, vec![]).unwrap();

        replace(&mut self.kpb, key_package_bundle)
    }

    /// Get the plain credential as byte vector.
    pub fn credential(&self) -> &[u8] {
        self.credential.credential().identity()
    }
}
