use crate::test_utils::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize;

use crate::{extensions::*, key_packages::*};

#[apply(ciphersuites_and_backends)]
fn generate_key_package(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let credential_bundle = CredentialBundle::new(
        vec![1, 2, 3],
        CredentialType::Basic,
        ciphersuite.into(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate a valid KeyPackage.
    let kpb = KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, vec![])
        .expect("An unexpected error occurred.");
    std::thread::sleep(std::time::Duration::from_millis(1));
    assert!(kpb.key_package().verify(backend).is_ok());
}

#[apply(ciphersuites_and_backends)]
fn decryption_key_index_computation(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let id = vec![1, 2, 3];
    let credential_bundle =
        CredentialBundle::new(id, CredentialType::Basic, ciphersuite.into(), backend)
            .expect("An unexpected error occurred.");
    let kpb = KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, Vec::new())
        .expect("An unexpected error occurred.")
        .unsigned();

    let kpb = kpb
        .sign(backend, &credential_bundle)
        .expect("An unexpected error occurred.");
    let enc = kpb
        .key_package()
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");

    // Now it's valid.
    let kp =
        KeyPackage::tls_deserialize(&mut enc.as_slice()).expect("An unexpected error occurred.");
    assert_eq!(kpb.key_package, kp);
}

#[apply(ciphersuites_and_backends)]
fn key_package_id_extension(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let id = vec![1, 2, 3];
    let credential_bundle =
        CredentialBundle::new(id, CredentialType::Basic, ciphersuite.into(), backend)
            .expect("An unexpected error occurred.");
    let kpb = KeyPackageBundle::new(&[ciphersuite], &credential_bundle, backend, vec![])
        .expect("An unexpected error occurred.");
    let verification = kpb.key_package().verify(backend);
    assert!(verification.is_ok());
    let mut kpb = kpb.unsigned();

    // Add an ID to the key package.
    let id = [1, 2, 3, 4];
    kpb.add_extension(Extension::ApplicationId(ApplicationIdExtension::new(&id)));

    // Sign it to make it valid.
    let kpb = kpb
        .sign(backend, &credential_bundle)
        .expect("An unexpected error occurred.");
    assert!(kpb.key_package().verify(backend).is_ok());

    // Check ID
    assert_eq!(
        &id[..],
        kpb.key_package().application_id().expect("No key ID")
    );
}

#[apply(backends)]
fn test_mismatch(backend: &impl OpenMlsCryptoProvider) {
    // === KeyPackageBundle negative test ===

    let ciphersuite_name = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;

    let credential_bundle = CredentialBundle::new(
        vec![1, 2, 3],
        CredentialType::Basic,
        signature_scheme,
        backend,
    )
    .expect("Could not create credential bundle");

    assert_eq!(
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, backend, vec![],),
        Err(KeyPackageBundleNewError::CiphersuiteSignatureSchemeMismatch)
    );

    // === KeyPackageBundle positive test ===

    let ciphersuite_name = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signature_scheme = SignatureScheme::ED25519;

    let credential_bundle = CredentialBundle::new(
        vec![1, 2, 3],
        CredentialType::Basic,
        signature_scheme,
        backend,
    )
    .expect("Could not create credential bundle");

    assert!(
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, backend, vec![]).is_ok()
    );
}
