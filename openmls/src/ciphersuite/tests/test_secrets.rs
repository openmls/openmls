use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    ciphersuite::{Ciphersuite, Secret},
    test_utils::*,
    versions::ProtocolVersion,
};

#[apply(ciphersuites_and_backends)]
fn secret_init(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // These two secrets must be incompatible
    let default_secret =
        Secret::random(ciphersuite, backend, None).expect("Not enough randomness.");
    let draft_secret = Secret::random(ciphersuite, backend, ProtocolVersion::Mls10)
        .expect("Not enough randomness.");

    let derived_default_secret = default_secret.derive_secret(backend, "my_test_label");
    let derived_draft_secret = draft_secret.derive_secret(backend, "my_test_label");
    assert_ne!(derived_default_secret, derived_draft_secret);
}
