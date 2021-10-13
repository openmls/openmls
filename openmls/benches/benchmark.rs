#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::prelude::*;
use rust_crypto::RustCrypto;

fn criterion_kp_bundle(c: &mut Criterion) {
    for ciphersuite in Config::supported_ciphersuites() {
        c.bench_function(
            &format!(
                "KeyPackage create bundle with ciphersuite: {:?}",
                ciphersuite.name()
            ),
            move |b| {
                b.iter_with_setup(
                    || {
                        let crypto = &RustCrypto::default();
                        CredentialBundle::new(
                            vec![1, 2, 3],
                            CredentialType::Basic,
                            ciphersuite.signature_scheme(),
                            crypto,
                        )
                        .unwrap()
                    },
                    |credential_bundle: CredentialBundle| {
                        let crypto = &RustCrypto::default();
                        KeyPackageBundle::new(
                            &[ciphersuite.name()],
                            &credential_bundle,
                            crypto,
                            Vec::new(),
                        )
                        .unwrap();
                    },
                );
            },
        );
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    criterion_kp_bundle(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
