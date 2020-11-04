#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::prelude::*;

fn criterion_kp_bundle(c: &mut Criterion) {
    for &ciphersuite_name in Config::supported_ciphersuites() {
        c.bench_function(
            &format!(
                "KeyPackage create bundle with ciphersuite: {:?}",
                ciphersuite_name
            ),
            move |b| {
                b.iter_with_setup(
                    || {
                        CredentialBundle::new(
                            vec![1, 2, 3],
                            CredentialType::Basic,
                            ciphersuite_name,
                        )
                        .unwrap()
                    },
                    |credential_bundle: CredentialBundle| {
                        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new());
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
