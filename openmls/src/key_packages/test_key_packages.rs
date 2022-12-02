use crate::test_utils::*;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize;

use crate::key_packages::*;

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
    let lifetime = Lifetime::new(60);
    let kpb = KeyPackageBundle::new(ciphersuite, &credential_bundle, backend, lifetime, vec![])
        .expect("An unexpected error occurred.");
    std::thread::sleep(std::time::Duration::from_millis(1));
    assert!(kpb.key_package().verify(backend).is_ok());

    // Now we add an invalid lifetime.
    let lifetime = Lifetime::new(0);
    let kpb = KeyPackageBundle::new(ciphersuite, &credential_bundle, backend, lifetime, vec![])
        .expect("An unexpected error occurred.");
    std::thread::sleep(std::time::Duration::from_millis(1));
    assert!(kpb.key_package().verify(backend).is_err());
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
    let kpb = KeyPackageBundle::new(
        ciphersuite,
        &credential_bundle,
        backend,
        Lifetime::default(),
        Vec::new(),
    )
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
        KeyPackageBundle::new(
            ciphersuite_name,
            &credential_bundle,
            backend,
            Lifetime::default(),
            vec![],
        ),
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

    assert!(KeyPackageBundle::new(
        ciphersuite_name,
        &credential_bundle,
        backend,
        Lifetime::default(),
        vec![]
    )
    .is_ok());
}
