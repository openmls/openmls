#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::{measurement::WallTime, BenchmarkGroup, BenchmarkId, Criterion};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

/// Identifies one measurement point of a benchmark group by the two dimensions
/// we vary: the crypto provider and the ciphersuite.
fn bench_id(provider_name: &str, ciphersuite: Ciphersuite) -> BenchmarkId {
    BenchmarkId::new(provider_name, format!("{ciphersuite:?}"))
}

fn criterion_key_package(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    provider: &impl OpenMlsProvider,
) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        group.bench_function(bench_id(provider_name, ciphersuite), move |b| {
            b.iter_with_setup(
                || {
                    let credential = BasicCredential::new(vec![1, 2, 3]);
                    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
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
        });
    }
}

fn create_welcome(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    provider: &impl OpenMlsProvider,
) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        group.bench_function(bench_id(provider_name, ciphersuite), move |b| {
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
                        core::slice::from_ref(bob_key_package.key_package()),
                    ) {
                        Ok((_, welcome, _)) => welcome,
                        Err(e) => panic!("Could not add member to group: {e:?}"),
                    };
                },
            );
        });
    }
}

fn join_group(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    provider: &impl OpenMlsProvider,
) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        group.bench_function(bench_id(provider_name, ciphersuite), move |b| {
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
                        core::slice::from_ref(bob_key_package.key_package()),
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
                    let processed_welcome = ProcessedWelcome::new_from_welcome(
                        provider,
                        mls_group_create_config.join_config(),
                        welcome,
                    )
                    .unwrap();
                    let _bob_group = JoinBuilder::new(provider, processed_welcome)
                        .with_ratchet_tree(alice_group.export_ratchet_tree().into())
                        .replace_old_group()
                        .build()
                        .unwrap()
                        .into_group(provider)
                        .unwrap();
                },
            );
        });
    }
}

fn create_commit(
    group: &mut BenchmarkGroup<'_, WallTime>,
    provider_name: &str,
    provider: &impl OpenMlsProvider,
) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        group.bench_function(bench_id(provider_name, ciphersuite), move |b| {
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
                        core::slice::from_ref(bob_key_package.key_package()),
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
                    let processed_welcome = ProcessedWelcome::new_from_welcome(
                        provider,
                        mls_group_create_config.join_config(),
                        welcome,
                    )
                    .unwrap();
                    let bob_group = JoinBuilder::new(provider, processed_welcome)
                        .with_ratchet_tree(alice_group.export_ratchet_tree().into())
                        .replace_old_group()
                        .build()
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
        });
    }
}

/// Runs `bench` against a criterion group named `name`.
///
/// All providers have to be benchmarked into the same open group: criterion
/// generates a group's summary plot from the ids collected while the group is
/// alive.
fn bench_group(
    c: &mut Criterion,
    name: &str,
    bench: impl FnOnce(&mut BenchmarkGroup<'_, WallTime>),
) {
    let mut group = c.benchmark_group(name);
    bench(&mut group);
    group.finish();
}

fn criterion_benchmark(c: &mut Criterion) {
    let rust_crypto = OpenMlsRustCrypto::default();
    #[cfg(feature = "libcrux-provider")]
    let libcrux = openmls_libcrux_crypto::Provider::default();

    // One group per operation, holding a measurement per provider and
    // ciphersuite, so the group summary plot compares both dimensions.
    bench_group(c, "KeyPackage create bundle", |group| {
        criterion_key_package(group, "RustCrypto", &rust_crypto);
        #[cfg(feature = "libcrux-provider")]
        criterion_key_package(group, "libcrux", &libcrux);
    });
    bench_group(c, "Create a welcome message", |group| {
        create_welcome(group, "RustCrypto", &rust_crypto);
        #[cfg(feature = "libcrux-provider")]
        create_welcome(group, "libcrux", &libcrux);
    });
    bench_group(c, "Join a group", |group| {
        join_group(group, "RustCrypto", &rust_crypto);
        #[cfg(feature = "libcrux-provider")]
        join_group(group, "libcrux", &libcrux);
    });
    bench_group(c, "Create a commit", |group| {
        create_commit(group, "RustCrypto", &rust_crypto);
        #[cfg(feature = "libcrux-provider")]
        create_commit(group, "libcrux", &libcrux);
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
