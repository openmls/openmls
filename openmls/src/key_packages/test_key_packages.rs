use crate::test_utils::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize;

use crate::{extensions::*, key_packages::*};

/// Helper function to generate key packages
pub(crate) fn key_package(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
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
            backend,
            &signer,
            CredentialWithKey {
                credential: credential.clone(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .expect("An unexpected error occurred.");

    (key_package, credential, signer)
}

#[apply(ciphersuites_and_backends)]
fn generate_key_package(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (key_package, _credential, signature_keys) = key_package(ciphersuite, backend);

    let pk = OpenMlsSignaturePublicKey::new(
        signature_keys.public().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();
    assert!(key_package.verify_no_out(backend.crypto(), &pk).is_ok());
    // TODO[FK]: #819 #133 replace with `validate`
    assert!(KeyPackage::verify(&key_package, backend.crypto()).is_ok());
}

#[apply(ciphersuites_and_backends)]
fn serialization(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (key_package, _, _) = key_package(ciphersuite, backend);

    let encoded = key_package
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    let decoded_key_package = KeyPackage::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");
    assert_eq!(key_package, decoded_key_package);
}

#[apply(ciphersuites_and_backends)]
fn application_id_extension(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let credential = Credential::new(b"Sasha".to_vec(), CredentialType::Basic)
        .expect("An unexpected error occurred.");
    let signature_keys = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let pk = OpenMlsSignaturePublicKey::new(
        signature_keys.public().into(),
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
            &signature_keys,
            CredentialWithKey {
                signature_key: signature_keys.to_public_vec().into(),
                credential,
            },
        )
        .expect("An unexpected error occurred.");

    assert!(key_package.verify_no_out(backend.crypto(), &pk).is_ok());
    // TODO[FK]: #819 #133 replace with `validate`
    assert!(KeyPackage::verify(&key_package, backend.crypto()).is_ok());

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
