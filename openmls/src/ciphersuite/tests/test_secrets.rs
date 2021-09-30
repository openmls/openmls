use rust_crypto::RustCrypto;

use crate::{
    ciphersuite::{Ciphersuite, Secret},
    config::ProtocolVersion,
    test_utils::OpenMlsTestRand,
};

#[test]
fn secret_init() {
    let mut rng = OpenMlsTestRand::new();
    let crypto = &RustCrypto::default();
    let csuite = Ciphersuite::default();

    // These two secrets must be incompatible
    let default_secret = Secret::random(csuite, &mut rng, None);
    let draft_secret = Secret::random(csuite, &mut rng, ProtocolVersion::Mls10Draft11);

    let derived_default_secret = default_secret.derive_secret(crypto, "my_test_label");
    let derived_draft_secret = draft_secret.derive_secret(crypto, "my_test_label");
    assert_ne!(derived_default_secret, derived_draft_secret);
}

#[test]
#[should_panic]
fn secret_incompatible() {
    let mut rng = OpenMlsTestRand::new();
    let crypto = &RustCrypto::default();
    let csuite = Ciphersuite::default();

    // These two secrets must be incompatible
    let default_secret = Secret::random(csuite, &mut rng, None);
    let draft_secret = Secret::random(csuite, &mut rng, ProtocolVersion::Mls10Draft11);

    // This must panic because the two secrets have incompatible MLS versions.
    let _default_extracted = default_secret.hkdf_extract(crypto, &draft_secret);
}
