#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::prelude::*;

fn criterion_kp_bundle(c: &mut Criterion) {
    c.bench_function("KeyPackage create bundle", |b| {
        let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

        b.iter_with_setup(
            || {
                CredentialBundle::new(vec![1, 2, 3], CredentialType::Basic, ciphersuite_name)
                    .unwrap()
            },
            |credential_bundle: CredentialBundle| {
                KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new());
            },
        );
    });
}

fn criterion_benchmark(c: &mut Criterion) {
    criterion_kp_bundle(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
