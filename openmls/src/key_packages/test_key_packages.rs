use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::Deserialize;

use crate::config::*;
use crate::{extensions::*, key_packages::*};

#[test]
fn generate_key_package() {
    let crypto = OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let credential_bundle = CredentialBundle::new(
            vec![1, 2, 3],
            CredentialType::Basic,
            ciphersuite.name().into(),
            &crypto,
        )
        .expect("An unexpected error occurred.");

        // Generate a valid KeyPackage.
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            &crypto,
            vec![lifetime_extension],
        )
        .expect("An unexpected error occurred.");
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(kpb.key_package().verify(&crypto).is_ok());

        // Now we add an invalid lifetime.
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(0));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            &crypto,
            vec![lifetime_extension],
        )
        .expect("An unexpected error occurred.");
        std::thread::sleep(std::time::Duration::from_millis(1));
        assert!(kpb.key_package().verify(&crypto).is_err());

        // Now with two lifetime extensions, the key package should be invalid.
        let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            &crypto,
            vec![lifetime_extension.clone(), lifetime_extension],
        );
        assert!(kpb.is_err());
    }
}

#[test]
fn test_codec() {
    let crypto = OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle = CredentialBundle::new(
            id,
            CredentialType::Basic,
            ciphersuite.name().into(),
            &crypto,
        )
        .expect("An unexpected error occurred.");
        let mut kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            &crypto,
            Vec::new(),
        )
        .expect("An unexpected error occurred.")
        .unsigned();

        kpb.add_extension(Extension::LifeTime(LifetimeExtension::new(60)));
        let kpb = kpb
            .sign(&crypto, &credential_bundle)
            .expect("An unexpected error occurred.");
        let enc = kpb
            .key_package()
            .tls_serialize_detached()
            .expect("An unexpected error occurred.");

        // Now it's valid.
        let kp = KeyPackage::tls_deserialize(&mut enc.as_slice())
            .expect("An unexpected error occurred.");
        assert_eq!(kpb.key_package, kp);
    }
}

#[test]
fn key_package_id_extension() {
    let crypto = OpenMlsRustCrypto::default();

    for ciphersuite in Config::supported_ciphersuites() {
        let id = vec![1, 2, 3];
        let credential_bundle = CredentialBundle::new(
            id,
            CredentialType::Basic,
            ciphersuite.name().into(),
            &crypto,
        )
        .expect("An unexpected error occurred.");
        let kpb = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &credential_bundle,
            &crypto,
            vec![Extension::LifeTime(LifetimeExtension::new(60))],
        )
        .expect("An unexpected error occurred.");
        assert!(kpb.key_package().verify(&crypto).is_ok());
        let mut kpb = kpb.unsigned();

        // Add an ID to the key package.
        let id = [1, 2, 3, 4];
        kpb.add_extension(Extension::KeyPackageId(KeyIdExtension::new(&id)));

        // Sign it to make it valid.
        let kpb = kpb
            .sign(&crypto, &credential_bundle)
            .expect("An unexpected error occurred.");
        assert!(kpb.key_package().verify(&crypto).is_ok());

        // Check ID
        assert_eq!(&id[..], kpb.key_package().key_id().expect("No key ID"));
    }
}

#[test]
fn test_mismatch() {
    // === KeyPackageBundle negative test ===
    let crypto = OpenMlsRustCrypto::default();

    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signature_scheme = SignatureScheme::ECDSA_SECP256R1_SHA256;

    let credential_bundle = CredentialBundle::new(
        vec![1, 2, 3],
        CredentialType::Basic,
        signature_scheme,
        &crypto,
    )
    .expect("Could not create credential bundle");

    assert_eq!(
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, &crypto, vec![],),
        Err(KeyPackageError::CiphersuiteSignatureSchemeMismatch)
    );

    // === KeyPackageBundle positive test ===

    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let signature_scheme = SignatureScheme::ED25519;

    let credential_bundle = CredentialBundle::new(
        vec![1, 2, 3],
        CredentialType::Basic,
        signature_scheme,
        &crypto,
    )
    .expect("Could not create credential bundle");

    assert!(
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, &crypto, vec![]).is_ok()
    );
}
