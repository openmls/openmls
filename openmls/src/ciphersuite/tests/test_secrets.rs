use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{
    ciphersuite::{Ciphersuite, Secret},
    config::ProtocolVersion,
};

#[test]
fn secret_init() {
    let crypto = &OpenMlsRustCrypto::default();
    let csuite = Ciphersuite::default();

    // These two secrets must be incompatible
    let default_secret = Secret::random(csuite, crypto, None).expect("Not enough randomness.");
    let draft_secret = Secret::random(csuite, crypto, ProtocolVersion::Mls10Draft11)
        .expect("Not enough randomness.");

    let derived_default_secret = default_secret.derive_secret(crypto, "my_test_label");
    let derived_draft_secret = draft_secret.derive_secret(crypto, "my_test_label");
    assert_ne!(derived_default_secret, derived_draft_secret);
}

#[test]
#[should_panic]
fn secret_incompatible() {
    let crypto = &OpenMlsRustCrypto::default();
    let csuite = Ciphersuite::default();

    // These two secrets must be incompatible
    let default_secret = Secret::random(csuite, crypto, None).expect("Not enough randomness.");
    let draft_secret = Secret::random(csuite, crypto, ProtocolVersion::Mls10Draft11)
        .expect("Not enough randomness.");

    // This must panic because the two secrets have incompatible MLS versions.
    let _default_extracted = default_secret.hkdf_extract(crypto, &draft_secret);
}
