use crate::config::*;
use crate::{ciphersuite::*, credentials::CredentialBundle};
use std::convert::TryFrom;
use test_macros::ctest;

use crate::credentials::CredentialType::Basic;
use crate::key_packages::KeyPackageBundle;

use super::{KeyStore, KeyStoreError};

ctest!(key_storage {
    let ciphersuite_name = CiphersuiteName::try_from(_ciphersuite_code).unwrap();
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();

    let ks = KeyStore::default();

    let credential = ks
        .generate_credential(
            "Alice".as_bytes().to_vec(),
            Basic,
            ciphersuite.signature_scheme(),
        )
        .expect("Error while creating credential.")
        .clone();

    let key_package = ks
        .generate_key_package(&[ciphersuite.name()], &credential, Vec::new())
        .expect("Error while generating key package.")
        .clone();

    assert_eq!(&credential, key_package.credential());

    // Let's cause an error.

    // Generate a CredentialBundle externally and then try to use it to create a
    // key package bundle in the store.
    let cb_external = CredentialBundle::new(
        "Bob".as_bytes().to_vec(),
        Basic,
        ciphersuite.signature_scheme(),
    )
        .expect("Error while creating credential.");

    let kpb_external_cred_err = ks
        .generate_key_package(&[ciphersuite.name()], cb_external.credential(), Vec::new()).expect_err("No error while trying to generate a key package with unavailable credential bundle.");

    assert_eq!(kpb_external_cred_err, KeyStoreError::NoMatchingCredentialBundle);

    // Let's load the bundles
    let cb = ks
        .get_credential_bundle(credential.signature_key())
        .expect("Error while getting CredentialBundle from the store.");

    assert_eq!(cb.borrow().credential(), &credential);

    let kpb = ks
        .take_key_package_bundle(&key_package.hash())
        .expect("Error while getting KeyPackageBundle from the store.");

    assert_eq!(kpb.key_package(), &key_package);

    // Let' create some errors.

    // Generate a CredentialBundle externally and then try to load it from the store.
    let cb_external = CredentialBundle::new(
        "Bob".as_bytes().to_vec(),
        Basic,
        ciphersuite.signature_scheme(),
    )
    .expect("Error while creating credential.");

    assert_eq!(ks.get_credential_bundle(cb_external.credential().signature_key()).is_none(), true);

    let kpb_external = KeyPackageBundle::new(&[ciphersuite.name()], &cb_external, Vec::new())
        .expect("Error while generating key package.");

    assert_eq!(ks.take_key_package_bundle(&kpb_external.key_package().hash()).is_none(), true);

});
