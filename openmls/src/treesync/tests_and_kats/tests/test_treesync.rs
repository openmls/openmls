use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    credentials::{CredentialBundle, CredentialType::Basic},
    prelude::{Config, KeyPackageBundle},
    treesync::TreeSync,
};

#[test]
fn test_creation() {
    let backend = OpenMlsRustCrypto::default();
    // FIXME: use the macro here.
    for ciphersuite in Config::supported_ciphersuites() {
        let cb = CredentialBundle::new(b"test", Basic, ciphersuite.signature_scheme(), backend)
            .expect("error creating CB");
        let kpb = KeyPackageBundle::new(ciphersuites, credential_bundle, backend, extensions)
            .expect("error creating KPB");
        let (treesync, commit_secret) =
            TreeSync::new(backend, kpb).expect("error creating treesync instance");
        println!("tree hash: {:?}", treesync.tree_hash())
    }
}
