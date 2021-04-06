//! # Key package tests

use openmls::prelude::*;

#[macro_use]
mod utils;

ctest_ciphersuites!(key_package_generation, test(ciphersuite_name: CiphersuiteName) {
    println!("Testing ciphersuite {:?}", ciphersuite_name);
    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();

    let id = vec![1, 2, 3];
    let credential_bundle =
        CredentialBundle::new(id, CredentialType::Basic, ciphersuite.signature_scheme()).unwrap();
    let mut kpb =
        KeyPackageBundle::new(&[ciphersuite.name()], &credential_bundle, Vec::new()).unwrap();

    // After creation, the signature should be ok.
    assert!(kpb.key_package().verify().is_ok());

    {
        let extensions = kpb.key_package().extensions();

        // The capabilities extension must be present and valid.
        // It's added automatically.
        let capabilities_extension = extensions
            .iter()
            .find(|e| e.extension_type() == ExtensionType::Capabilities)
            .expect("Capabilities extension is missing in key package");
        let capabilities_extension = capabilities_extension.to_capabilities_extension().unwrap();

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
        let _lifetime_extension = lifetime_extension.to_lifetime_extension().unwrap();
    }

    // Add and retrieve a key package ID.
    let key_id = [1, 2, 3, 4, 5, 6, 7];
    kpb.key_package_mut()
        .add_extension(Box::new(KeyIdExtension::new(&key_id)));

    // The key package is invalid because the signature is invalid now.
    assert!(kpb.key_package().verify().is_err());

    // After re-signing the package it is valid.
    kpb.key_package_mut().sign(&credential_bundle);
    assert!(kpb.key_package().verify().is_ok());

    // Get the key ID extension.
    let extensions = kpb.key_package().extensions();
    let key_id_extension = extensions
        .iter()
        .find(|e| e.extension_type() == ExtensionType::KeyId)
        .expect("Key ID extension is missing in key package");
    let key_id_extension = key_id_extension.to_key_id_extension().unwrap();
    assert_eq!(&key_id, key_id_extension.as_slice());
});
