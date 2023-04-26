use openmls_test::openmls_test;

use crate::{ciphersuite::Secret, versions::ProtocolVersion};

#[openmls_test]
fn secret_init() {
    // These two secrets must be incompatible
    let default_secret =
        Secret::random(ciphersuite, backend, None).expect("Not enough randomness.");
    let draft_secret = Secret::random(ciphersuite, backend, ProtocolVersion::Mls10Draft11)
        .expect("Not enough randomness.");

    let derived_default_secret = default_secret.derive_secret(backend, "my_test_label");
    let derived_draft_secret = draft_secret.derive_secret(backend, "my_test_label");
    assert_ne!(derived_default_secret, derived_draft_secret);
}

#[should_panic]
#[openmls_test]
fn secret_incompatible() {
    // These two secrets must be incompatible
    let default_secret =
        Secret::random(ciphersuite, backend, None).expect("Not enough randomness.");
    let draft_secret = Secret::random(ciphersuite, backend, ProtocolVersion::Mls10Draft11)
        .expect("Not enough randomness.");

    // This must panic because the two secrets have incompatible MLS versions.
    let _default_extracted = default_secret.hkdf_extract(backend, &draft_secret);
}
