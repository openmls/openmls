#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

fn criterion_key_package(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        c.bench_function(
            &format!("KeyPackage create bundle with ciphersuite: {ciphersuite:?}"),
            move |b| {
                b.iter_with_setup(
                    || {
                        let credential = BasicCredential::new(vec![1, 2, 3]);
                        let signer =
                            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                        let credential_with_key = CredentialWithKey {
                            credential: credential.into(),
                            signature_key: signer.to_public_vec().into(),
                        };

                        (credential_with_key, signer)
                    },
                    |(credential_with_key, signer)| {
                        let _key_package = KeyPackage::builder()
                            .build(ciphersuite, provider, &signer, credential_with_key)
                            .expect("An unexpected error occurred.");
                    },
                );
            },
        );
    }
}

fn create_welcome(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        c.bench_function(
            &format!("Create a welcome message with ciphersuite: {ciphersuite:?}"),
            move |b| {
                b.iter_with_setup(
                    || {
                        let alice_credential = BasicCredential::new("Alice".into());
                        let alice_signer =
                            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                        let alice_credential_with_key = CredentialWithKey {
                            credential: alice_credential.into(),
                            signature_key: alice_signer.to_public_vec().into(),
                        };

                        let bob_credential = BasicCredential::new("Bob".into());
                        let bob_signer =
                            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                        let bob_credential_with_key = CredentialWithKey {
                            credential: bob_credential.into(),
                            signature_key: bob_signer.to_public_vec().into(),
                        };
                        let bob_key_package = KeyPackage::builder()
                            .build(
                                ciphersuite,
                                provider,
                                &bob_signer,
                                bob_credential_with_key.clone(),
                            )
                            .expect("An unexpected error occurred.");

                        let mls_group_create_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();

                        // === Alice creates a group ===
                        let alice_group = MlsGroup::new(
                            provider,
                            &alice_signer,
                            &mls_group_create_config,
                            alice_credential_with_key.clone(),
                        )
                        .expect("An unexpected error occurred.");

                        (alice_signer, alice_group, bob_key_package)
                    },
                    |(alice_signer, mut alice_group, bob_key_package)| {
                        let _welcome = match alice_group.add_members(
                            provider,
                            &alice_signer,
                            &[bob_key_package.key_package().clone()],
                        ) {
                            Ok((_, welcome, _)) => welcome,
                            Err(e) => panic!("Could not add member to group: {e:?}"),
                        };
                    },
                );
            },
        );
    }
}

fn join_group(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        c.bench_function(
            &format!("Join a group with ciphersuite: {ciphersuite:?}"),
            move |b| {
                b.iter_with_setup(
                    || {
                        let alice_credential = BasicCredential::new("Alice".into());
                        let alice_signer =
                            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                        let alice_credential_with_key = CredentialWithKey {
                            credential: alice_credential.into(),
                            signature_key: alice_signer.to_public_vec().into(),
                        };

                        let bob_credential = BasicCredential::new("Bob".into());
                        let bob_signer =
                            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                        let bob_credential_with_key = CredentialWithKey {
                            credential: bob_credential.into(),
                            signature_key: bob_signer.to_public_vec().into(),
                        };
                        let bob_key_package = KeyPackage::builder()
                            .build(
                                ciphersuite,
                                provider,
                                &bob_signer,
                                bob_credential_with_key.clone(),
                            )
                            .expect("An unexpected error occurred.");

                        let mls_group_create_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();

                        // === Alice creates a group ===
                        let mut alice_group = MlsGroup::new(
                            provider,
                            &alice_signer,
                            &mls_group_create_config,
                            alice_credential_with_key.clone(),
                        )
                        .expect("An unexpected error occurred.");

                        let welcome = match alice_group.add_members(
                            provider,
                            &alice_signer,
                            &[bob_key_package.key_package().clone()],
                        ) {
                            Ok((_, welcome, _)) => welcome,
                            Err(e) => panic!("Could not add member to group: {e:?}"),
                        };

                        alice_group
                            .merge_pending_commit(provider)
                            .expect("error merging pending commit");

                        (alice_group, mls_group_create_config, welcome)
                    },
                    |(alice_group, mls_group_create_config, welcome)| {
                        let welcome: MlsMessageIn = welcome.into();
                        let welcome = welcome
                            .into_welcome()
                            .expect("expected the message to be a welcome message");
                        let _bob_group = StagedWelcome::new_from_welcome(
                            provider,
                            mls_group_create_config.join_config(),
                            welcome,
                            Some(alice_group.export_ratchet_tree().into()),
                        )
                        .unwrap()
                        .into_group(provider);
                    },
                );
            },
        );
    }
}

fn create_commit(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        c.bench_function(
            &format!("Create a commit with ciphersuite: {ciphersuite:?}"),
            move |b| {
                b.iter_with_setup(
                    || {
                        let alice_credential = BasicCredential::new("Alice".into());
                        let alice_signer =
                            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                        let alice_credential_with_key = CredentialWithKey {
                            credential: alice_credential.into(),
                            signature_key: alice_signer.to_public_vec().into(),
                        };

                        let bob_credential = BasicCredential::new("Bob".into());
                        let bob_signer =
                            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                        let bob_credential_with_key = CredentialWithKey {
                            credential: bob_credential.into(),
                            signature_key: bob_signer.to_public_vec().into(),
                        };
                        let bob_key_package = KeyPackage::builder()
                            .build(
                                ciphersuite,
                                provider,
                                &bob_signer,
                                bob_credential_with_key.clone(),
                            )
                            .expect("An unexpected error occurred.");

                        let mls_group_create_config = MlsGroupCreateConfig::builder()
                            .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
                            .ciphersuite(ciphersuite)
                            .build();

                        // === Alice creates a group ===
                        let mut alice_group = MlsGroup::new(
                            provider,
                            &alice_signer,
                            &mls_group_create_config,
                            alice_credential_with_key.clone(),
                        )
                        .expect("An unexpected error occurred.");

                        let welcome = match alice_group.add_members(
                            provider,
                            &alice_signer,
                            &[bob_key_package.key_package().clone()],
                        ) {
                            Ok((_, welcome, _)) => welcome,
                            Err(e) => panic!("Could not add member to group: {e:?}"),
                        };

                        alice_group
                            .merge_pending_commit(provider)
                            .expect("error merging pending commit");

                        let welcome: MlsMessageIn = welcome.into();
                        let welcome = welcome
                            .into_welcome()
                            .expect("expected the message to be a welcome message");
                        let bob_group = StagedWelcome::new_from_welcome(
                            provider,
                            mls_group_create_config.join_config(),
                            welcome,
                            Some(alice_group.export_ratchet_tree().into()),
                        )
                        .unwrap()
                        .into_group(provider)
                        .unwrap();

                        (bob_group, bob_signer)
                    },
                    |(mut bob_group, bob_signer)| {
                        let _ = bob_group
                            .self_update(provider, &bob_signer, LeafNodeParameters::default())
                            .unwrap();

                        bob_group
                            .merge_pending_commit(provider)
                            .expect("error merging pending commit");
                    },
                );
            },
        );
    }
}

fn kp_bundle_rust_crypto(c: &mut Criterion) {
    let provider = &OpenMlsRustCrypto::default();
    println!("provider: RustCrypto");
    criterion_key_package(c, provider);
}

fn criterion_benchmark(c: &mut Criterion) {
    kp_bundle_rust_crypto(c);
    criterion_key_package(c, &openmls_libcrux_crypto::Provider::default());
    create_welcome(c, &openmls_libcrux_crypto::Provider::default());
    join_group(c, &openmls_libcrux_crypto::Provider::default());
    create_commit(c, &openmls_libcrux_crypto::Provider::default());
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
