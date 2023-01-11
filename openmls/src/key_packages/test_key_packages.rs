use crate::test_utils::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize;

use crate::{extensions::*, key_packages::*};

/// Helper function to generate key packages
fn key_package(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (KeyPackage, CredentialBundle) {
    let credential_bundle = CredentialBundle::new(
        b"Sasha".to_vec(),
        CredentialType::Basic,
        ciphersuite.into(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate a valid KeyPackage.
    let key_package = KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            &credential_bundle,
        )
        .expect("An unexpected error occurred.");

    (key_package, credential_bundle)
}

#[apply(ciphersuites_and_backends)]
fn generate_key_package(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (key_package, credential_bundle) = key_package(ciphersuite, backend);

    assert!(key_package
        .verify_no_out(
            backend,
            credential_bundle.credential().signature_key(),
            ciphersuite.signature_algorithm()
        )
        .is_ok());
    // TODO[FK]: #819 #133 replace with `validate`
    assert!(KeyPackage::verify(&key_package, backend, ciphersuite).is_ok());
}

#[apply(ciphersuites_and_backends)]
fn serialization(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (key_package, _) = key_package(ciphersuite, backend);

    let encoded = key_package
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let decoded_key_package = KeyPackage::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(key_package, decoded_key_package);
}

#[apply(ciphersuites_and_backends)]
fn application_id_extension(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // This is a leaf node extension but it is set through the key package.
    let credential_bundle = CredentialBundle::new(
        b"Sasha".to_vec(),
        CredentialType::Basic,
        ciphersuite.into(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate a valid KeyPackage.
    let id = b"application id" as &[u8];
    let key_package = KeyPackage::builder()
        .leaf_node_extensions(Extensions::single(Extension::ApplicationId(
            ApplicationIdExtension::new(id),
        )))
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            &credential_bundle,
        )
        .expect("An unexpected error occurred.");

    assert!(key_package
        .verify_no_out(
            backend,
            credential_bundle.credential().signature_key(),
            ciphersuite.signature_algorithm()
        )
        .is_ok());
    // TODO[FK]: #819 #133 replace with `validate`
    assert!(KeyPackage::verify(&key_package, backend, ciphersuite).is_ok());

    // Check ID
    assert_eq!(
        Some(id),
        key_package
            .leaf_node()
            .extensions()
            .application_id()
            .map(|e| e.as_slice())
    );
}
