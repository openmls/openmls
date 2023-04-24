use crate::test_utils::*;
use openmls_basic_credential::OpenMlsBasicCredential;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize;

use crate::{extensions::*, key_packages::*};

/// Helper function to generate key packages
pub(crate) fn key_package(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (KeyPackage, OpenMlsBasicCredential) {
    let credential =
        OpenMlsBasicCredential::new(ciphersuite.signature_algorithm(), b"Sasha".to_vec()).unwrap();

    // Generate a valid KeyPackage.
    let key_package = KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            &credential,
            &credential,
        )
        .expect("An unexpected error occurred.");

    (key_package, credential)
}

#[apply(ciphersuites_and_backends)]
fn generate_key_package(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (key_package, credential) = key_package(ciphersuite, backend);

    let kpi = KeyPackageIn::from(key_package);
    assert!(kpi.validate(backend.crypto()).is_ok());
}

#[apply(ciphersuites_and_backends)]
fn serialization(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (key_package, _) = key_package(ciphersuite, backend);

    let encoded = key_package
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let decoded_key_package = KeyPackage::from(
        KeyPackageIn::tls_deserialize(&mut encoded.as_slice())
            .expect("An unexpected error occurred."),
    );
    assert_eq!(key_package, decoded_key_package);
}

#[apply(ciphersuites_and_backends)]
fn application_id_extension(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let credential =
        OpenMlsBasicCredential::new(ciphersuite.signature_algorithm(), b"Sasha".to_vec()).unwrap();
    let pk = OpenMlsSignaturePublicKey::new(
        credential.public().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

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
            &credential,
            &credential,
        )
        .expect("An unexpected error occurred.");

    let kpi = KeyPackageIn::from(key_package.clone());
    assert!(kpi.validate(backend.crypto()).is_ok());

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
