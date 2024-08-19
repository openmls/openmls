use crate::test_utils::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::prelude::*;

use tls_codec::Deserialize;

use crate::{extensions::*, key_packages::*, storage::OpenMlsProvider};

/// Helper function to generate key packages
pub(crate) fn key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
) -> (KeyPackageBundle, Credential, SignatureKeyPair) {
    let credential = BasicCredential::new(b"Sasha".to_vec());
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // Generate a valid KeyPackage.
    let key_package = KeyPackage::builder()
        .build(
            ciphersuite,
            provider,
            &signer,
            CredentialWithKey {
                credential: credential.clone().into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("An unexpected error occurred.");

    (key_package, credential.into(), signer)
}

#[openmls_test::openmls_test]
fn generate_key_package() {
    let (key_package, _credential, _signature_keys) = key_package(ciphersuite, provider);

    let kpi = KeyPackageIn::from(key_package.key_package().clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());
}

#[openmls_test::openmls_test]
fn serialization() {
    let (key_package, _, _) = key_package(ciphersuite, provider);

    let encoded = key_package
        .key_package()
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let decoded_key_package = KeyPackage::from(
        KeyPackageIn::tls_deserialize(&mut encoded.as_slice())
            .expect("An unexpected error occurred."),
    );
    assert_eq!(key_package.key_package(), &decoded_key_package);
}

#[openmls_test::openmls_test]
fn application_id_extension() {
    let credential = BasicCredential::new(b"Sasha".to_vec());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // Generate a valid KeyPackage.
    let id = b"application id" as &[u8];
    let key_package = KeyPackage::builder()
        .leaf_node_extensions(Extensions::single(Extension::ApplicationId(
            ApplicationIdExtension::new(id),
        )))
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.into(),
            },
        )
        .expect("An unexpected error occurred.");

    let kpi = KeyPackageIn::from(key_package.key_package().clone());
    assert!(kpi
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .is_ok());

    // Check ID
    assert_eq!(
        Some(id),
        key_package
            .key_package()
            .leaf_node()
            .extensions()
            .application_id()
            .map(|e| e.as_slice())
    );
}

/// Test that the key package is correctly validated:
/// - The protocol version is correct
/// - The init key is not equal to the encryption key
#[openmls_test::openmls_test]
fn key_package_validation() {
    let (key_package_orig, _, _) = key_package(ciphersuite, provider);

    // === Protocol version ===

    let mut franken_key_package =
        frankenstein::FrankenKeyPackage::from(key_package_orig.key_package().clone());
    // Set an invalid protocol version
    franken_key_package.protocol_version = 999;

    let key_package_in = KeyPackageIn::from(franken_key_package);

    let err = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_err();

    // Expect an invalid protocol version error
    assert_eq!(err, KeyPackageVerifyError::InvalidProtocolVersion);

    // === Init/encryption key ===

    let mut franken_key_package =
        frankenstein::FrankenKeyPackage::from(key_package_orig.key_package().clone());
    // Set an invalid init key
    franken_key_package.init_key = franken_key_package.leaf_node.encryption_key.clone();

    let key_package_in = KeyPackageIn::from(franken_key_package);

    let err = key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .unwrap_err();

    // Expect an invalid init/encryption key error
    assert_eq!(err, KeyPackageVerifyError::InitKeyEqualsEncryptionKey);
}

/// Test that a key package is correctly built with a last resort extension when
/// the last resort flag is set during the build process.
#[openmls_test::openmls_test]
fn last_resort_key_package() {
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()));
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // build without any other extensions
    let key_package = KeyPackage::builder()
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.key_package().last_resort());

    // build with empty extensions
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.key_package().last_resort());

    // build with extension
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::single(Extension::Unknown(
            0xFF00,
            UnknownExtension(vec![0x00]),
        )))
        .mark_as_last_resort()
        .build(
            ciphersuite,
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.key_package().last_resort());
}
