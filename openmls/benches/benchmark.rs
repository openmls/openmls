#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

fn criterion_kp_bundle(c: &mut Criterion, provider: &impl OpenMlsProvider) {
    for &ciphersuite in provider.crypto().supported_ciphersuites().iter() {
        c.bench_function(
            &format!("KeyPackage create bundle with ciphersuite: {ciphersuite:?}"),
            move |b| {
                b.iter_with_setup(
                    || {
                        let credential =
                            Credential::new(vec![1, 2, 3], CredentialType::Basic).unwrap();
                        let signer =
                            SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
                        let credential_with_key = CredentialWithKey {
                            credential,
                            signature_key: signer.to_public_vec().into(),
                        };

                        (credential_with_key, signer)
                    },
                    |(credential_with_key, signer)| {
                        let _key_package = KeyPackage::builder()
                            .build(
                                CryptoConfig {
                                    ciphersuite,
                                    version: ProtocolVersion::default(),
                                },
                                provider,
                                &signer,
                                credential_with_key,
                            )
                            .expect("An unexpected error occurred.");
                    },
                );
            },
        );
    }
}

fn kp_bundle_rust_crypto(c: &mut Criterion) {
    let provider = &OpenMlsRustCrypto::default();
    println!("provider: RustCrypto");
    criterion_kp_bundle(c, provider);
}

fn criterion_benchmark(c: &mut Criterion) {
    kp_bundle_rust_crypto(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
