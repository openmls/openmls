//! # Key package tests

use openmls::ciphersuite::signable::Signable;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

#[macro_use]
mod utils;

ctest_ciphersuites!(key_package_generation, test(ciphersuite_name: CiphersuiteName) {
    let crypto = OpenMlsRustCrypto::default();
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).expect("An unexpected error occurred.");

    let id = vec![1, 2, 3];
    let credential_bundle =
        CredentialBundle::new(id, CredentialType::Basic, ciphersuite.signature_scheme(),&crypto).expect("An unexpected error occurred.");
    let kpb =
        KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle,&crypto, Vec::new()).expect("An unexpected error occurred.");

    // After creation, the signature should be ok.
    assert!(kpb.key_package().verify(&crypto).is_ok());

    {
        let extensions = kpb.key_package().extensions();

        // The capabilities extension must be present and valid.
        // It's added automatically.
        let capabilities_extension = extensions
            .iter()
            .find(|e| e.extension_type() == ExtensionType::Capabilities)
            .expect("Capabilities extension is missing in key package");
        let capabilities_extension = capabilities_extension.as_capabilities_extension().expect("An unexpected error occurred.");

        // Only the single ciphersuite is set.
        assert_eq!(1, capabilities_extension.ciphersuites().len());
        assert_eq!(ciphersuite_name, capabilities_extension.ciphersuites()[0]);

        // Check supported versions.
        assert_eq!(
            Config::supported_versions(),
            capabilities_extension.versions()
        );

        // Check supported extensions.
        assert_eq!(
            Config::supported_extensions(),
            capabilities_extension.extensions()
        );

        // Get the lifetime extension. It's added automatically.
        let lifetime_extension = extensions
            .iter()
            .find(|e| e.extension_type() == ExtensionType::Lifetime)
            .expect("Lifetime extension is missing in key package");
        let _lifetime_extension = lifetime_extension.as_lifetime_extension().expect("An unexpected error occurred.");
    }

    // Add and retrieve a key package ID.
    let key_id = [1, 2, 3, 4, 5, 6, 7];
    let mut kpb_unsigned: KeyPackageBundlePayload = kpb.into();
    kpb_unsigned.add_extension(Extension::KeyPackageId(KeyIdExtension::new(&key_id)));

    // After re-signing the package it is valid.
    let kpb = kpb_unsigned.sign(&crypto, &credential_bundle).expect("An unexpected error occurred.");
    assert!(kpb.key_package().verify(&crypto).is_ok());

    // Get the key ID extension.
    let extensions = kpb.key_package().extensions();
    let key_id_extension = extensions
        .iter()
        .find(|e| e.extension_type() == ExtensionType::KeyId)
        .expect("Key ID extension is missing in key package");
    let key_id_extension = key_id_extension.as_key_id_extension().expect("An unexpected error occurred.");
    assert_eq!(&key_id, key_id_extension.as_slice());
});
