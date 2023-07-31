use crate::test_utils::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize;

use crate::{extensions::*, key_packages::*};

/// Helper function to generate key packages
pub(crate) fn key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> (KeyPackage, Credential, SignatureKeyPair) {
    let credential = Credential::new(b"Sasha".to_vec(), CredentialType::Basic).unwrap();
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // Generate a valid KeyPackage.
    let key_package = KeyPackage::builder()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            provider,
            &signer,
            CredentialWithKey {
                credential: credential.clone(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("An unexpected error occurred.");

    (key_package, credential, signer)
}

#[apply(ciphersuites_and_providers)]
fn generate_key_package(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (key_package, _credential, _signature_keys) = key_package(ciphersuite, provider);

    let kpi = KeyPackageIn::from(key_package);
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());
}

#[apply(ciphersuites_and_providers)]
fn serialization(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (key_package, _, _) = key_package(ciphersuite, provider);

    let encoded = key_package
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let decoded_key_package = KeyPackage::from(
        KeyPackageIn::tls_deserialize(&mut encoded.as_slice())
            .expect("An unexpected error occurred."),
    );
    assert_eq!(key_package, decoded_key_package);
}

#[apply(ciphersuites_and_providers)]
fn application_id_extension(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let credential = Credential::new(b"Sasha".to_vec(), CredentialType::Basic)
        .expect("An unexpected error occurred.");
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

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
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect("An unexpected error occurred.");

    let kpi = KeyPackageIn::from(key_package.clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());

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

/// Test that the key package is correctly validated:
/// - The protocol version is correct
/// - The init key is not equal to the encryption key
#[apply(ciphersuites_and_providers)]
fn key_package_validation(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let (key_package_orig, _, _) = key_package(ciphersuite, provider);

    // === Protocol version ===

    let mut key_package = key_package_orig.clone();

    // Set an invalid protocol version
    key_package.set_version(ProtocolVersion::Mls10Draft11);

    let encoded = key_package
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let key_package_in = KeyPackageIn::tls_deserialize(&mut encoded.as_slice()).unwrap();
    let err = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_err();

    // Expect an invalid protocol version error
    assert_eq!(err, KeyPackageVerifyError::InvalidProtocolVersion);

    // === Init/encryption key ===

    let mut key_package = key_package_orig;

    // Set an invalid init key
    key_package.set_init_key(key_package.leaf_node().encryption_key().key().clone());

    let encoded = key_package
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let key_package_in = KeyPackageIn::tls_deserialize(&mut encoded.as_slice()).unwrap();
    let err = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_err();

    // Expect an invalid init/encryption key error
    assert_eq!(err, KeyPackageVerifyError::InitKeyEqualsEncryptionKey);
}
