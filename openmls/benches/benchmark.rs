#[macro_use]
extern crate criterion;
extern crate openmls;
extern crate rand;

use criterion::Criterion;
use openmls::prelude::{config::CryptoConfig, *};
use openmls_basic_credential::OpenMlsBasicCredential;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};

fn criterion_kp_bundle(c: &mut Criterion, backend: &impl OpenMlsCryptoProvider) {
    for &ciphersuite in backend.crypto().supported_ciphersuites().iter() {
        c.bench_function(
            &format!("KeyPackage create bundle with ciphersuite: {ciphersuite:?}"),
            move |b| {
                b.iter_with_setup(
                    || {
                        let credential = OpenMlsBasicCredential::new(
                            ciphersuite.signature_algorithm(),
                            "identity".into(),
                        )
                        .unwrap();

                        credential
                    },
                    |credential| {
                        let _key_package = KeyPackage::builder()
                            .build(
                                CryptoConfig {
                                    ciphersuite,
                                    version: ProtocolVersion::default(),
                                },
                                backend,
                                &credential,
                                &credential,
                            )
                            .expect("An unexpected error occurred.");
                    },
                );
            },
        );
    }
}

fn kp_bundle_rust_crypto(c: &mut Criterion) {
    let backend = &OpenMlsRustCrypto::default();
    println!("Backend: RustCrypto");
    criterion_kp_bundle(c, backend);
}

#[cfg(feature = "evercrypt")]
fn kp_bundle_evercrypt(c: &mut Criterion) {
    use openmls_evercrypt::OpenMlsEvercrypt;
    let backend = &OpenMlsEvercrypt::default();
    println!("Backend: Evercrypt");
    criterion_kp_bundle(c, backend);
}

fn criterion_benchmark(c: &mut Criterion) {
    kp_bundle_rust_crypto(c);
    #[cfg(feature = "evercrypt")]
    kp_bundle_evercrypt(c);
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
