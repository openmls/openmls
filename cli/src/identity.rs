use std::mem::replace;

use openmls::prelude::*;

pub struct Identity {
    pub(crate) kpb: KeyPackageBundle,
    pub(crate) credential: CredentialBundle,
}

impl Identity {
    pub(crate) fn new(ciphersuite: CiphersuiteName, id: &[u8]) -> Self {
        let credential_bundle =
            CredentialBundle::new(id.to_vec(), CredentialType::Basic, ciphersuite).unwrap();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &credential_bundle, vec![]).unwrap();
        Self {
            kpb: key_package_bundle,
            credential: credential_bundle,
        }
    }
    pub fn update(&mut self) -> KeyPackageBundle {
        let ciphersuite = self.kpb.key_package().ciphersuite();
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite], &self.credential, vec![]).unwrap();

        let out = replace(&mut self.kpb, key_package_bundle);
        out
    }
}
