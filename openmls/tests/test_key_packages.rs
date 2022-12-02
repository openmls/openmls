//! # Key package tests

use openmls::{prelude::*, test_utils::*, *};

#[apply(ciphersuites_and_backends)]
fn key_package_generation(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    println!("Testing ciphersuite {:?}", ciphersuite);

    let id = vec![1, 2, 3];
    let credential_bundle = CredentialBundle::new(
        id,
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let kpb = KeyPackageBundle::new(ciphersuite, &credential_bundle, backend, Vec::new())
        .expect("An unexpected error occurred.");

    // After creation, the signature should be ok.
    assert!(kpb.key_package().verify(backend).is_ok());

    {
        let extensions = kpb.key_package().extensions();

        // The capabilities extension must be present and valid.
        // It's added automatically.
        let capabilities_extension = extensions
            .iter()
            .find(|e| e.extension_type() == ExtensionType::Capabilities)
            .expect("Capabilities extension is missing in key package");
        let capabilities_extension = capabilities_extension
            .as_capabilities_extension()
            .expect("An unexpected error occurred.");

        // Only the single ciphersuite is set.
        assert_eq!(1, capabilities_extension.ciphersuites().len());
        assert_eq!(ciphersuite, capabilities_extension.ciphersuites()[0]);

        // Check supported versions.
        assert_eq!(&[ProtocolVersion::Mls10], capabilities_extension.versions());

        // Check supported extensions.
        assert_eq!(
            vec![
                ExtensionType::Capabilities,
                ExtensionType::Lifetime,
                ExtensionType::ApplicationId
            ],
            capabilities_extension.extensions()
        );
    }

    // Add and retrieve a key package ID.
    let key_id = [1, 2, 3, 4, 5, 6, 7];
    let mut kpb_unsigned: KeyPackageBundlePayload = kpb.into();
    kpb_unsigned.add_extension(Extension::ApplicationId(ApplicationIdExtension::new(
        &key_id,
    )));

    // After re-signing the package it is valid.
    let kpb = kpb_unsigned
        .sign(backend, &credential_bundle)
        .expect("An unexpected error occurred.");
    assert!(kpb.key_package().verify(backend).is_ok());

    // Get the key ID extension.
    let extensions = kpb.key_package().extensions();
    let key_id_extension = extensions
        .iter()
        .find(|e| e.extension_type() == ExtensionType::ApplicationId)
        .expect("Key ID extension is missing in key package");
    let key_id_extension = key_id_extension
        .as_application_id_extension()
        .expect("An unexpected error occurred.");
    assert_eq!(&key_id, key_id_extension.as_slice());
}
