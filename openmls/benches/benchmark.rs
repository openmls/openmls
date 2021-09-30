#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::{prelude::*, test_utils::OpenMlsTestRand};
use rust_crypto::RustCrypto;

fn criterion_kp_bundle(c: &mut Criterion) {
    let crypto = &RustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        c.bench_function(
            &format!(
                "KeyPackage create bundle with ciphersuite: {:?}",
                ciphersuite.name()
            ),
            move |b| {
                b.iter_with_setup(
                    || {
                        let mut rng = OpenMlsTestRand::new();
                        CredentialBundle::new(
                            vec![1, 2, 3],
                            CredentialType::Basic,
                            ciphersuite.signature_scheme(),
                            &mut rng,
                            crypto,
                        )
                        .unwrap()
                    },
                    |credential_bundle: CredentialBundle| {
                        let mut rng = OpenMlsTestRand::new();
                        KeyPackageBundle::new(
                            &[ciphersuite.name()],
                            &credential_bundle,
                            &mut rng,
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
