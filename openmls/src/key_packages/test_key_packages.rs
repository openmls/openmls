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
    let credential = BasicCredential::new(b"Sasha".to_vec()).unwrap();
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
                credential: credential.clone().into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("An unexpected error occurred.");

    (key_package, credential.into(), signer)
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
    let credential = BasicCredential::new(b"Sasha".to_vec()).unwrap();
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
                credential: credential.into(),
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
    key_package.set_init_key(InitKey::from(
        key_package
            .leaf_node()
            .encryption_key()
            .key()
            .as_slice()
            .to_vec(),
    ));

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

/// Test that a key package is correctly built with a last resort extension when
/// the last resort flag is set during the build process.
#[apply(ciphersuites_and_providers)]
fn last_resort_key_package(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let credential = Credential::from(BasicCredential::new(b"Sasha".to_vec()).unwrap());
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    // build without any other extensions
    let key_package = KeyPackage::builder()
        .mark_as_last_resort()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.last_resort());

    // build with empty extensions
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::empty())
        .mark_as_last_resort()
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            provider,
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential: credential.clone(),
            },
        )
        .expect("An unexpected error occurred.");
    assert!(key_package.last_resort());

    // build with extension
    let key_package = KeyPackage::builder()
        .key_package_extensions(Extensions::single(Extension::Unknown(
            0xFF00,
            UnknownExtension(vec![0x00]),
        )))
        .mark_as_last_resort()
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
    assert!(key_package.last_resort());
}
