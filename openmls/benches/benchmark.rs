#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::group::prelude::*;
use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

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
                        let crypto = &OpenMlsRustCrypto::default();
                        CredentialBundle::new(
                            vec![1, 2, 3],
                            CredentialType::Basic,
                            ciphersuite.signature_scheme(),
                            crypto,
                        )
                        .expect("An unexpected error occurred.")
                    },
                    |credential_bundle: CredentialBundle| {
                        let crypto = &OpenMlsRustCrypto::default();
                        KeyPackageBundle::new(
                            &[ciphersuite.name()],
                            &credential_bundle,
                            crypto,
                            Vec::new(),
                        )
                        .expect("An unexpected error occurred.");
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
