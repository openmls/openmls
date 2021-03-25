use crate::config::ProtocolVersion;

use super::{Ciphersuite, Secret};

#[test]
fn secret_init() {
    pretty_env_logger::init();

    let csuite = Ciphersuite::default();

    // These two secrets must be incompatible
    let default_secret = Secret::random(csuite, None);
    let draft_secret = Secret::random(csuite, ProtocolVersion::Mls10Draft12);

    let derived_default_secret = default_secret.derive_secret("my_test_label");
    let derived_draft_secret = draft_secret.derive_secret("my_test_label");
    assert_ne!(derived_default_secret, derived_draft_secret);
}

#[test]
#[should_panic]
fn secret_incompatible() {
    let csuite = Ciphersuite::default();

    // These two secrets must be incompatible
    let default_secret = Secret::random(csuite, None);
    let draft_secret = Secret::random(csuite, ProtocolVersion::Mls10Draft12);

    // This must panic because the two secrets have incompatible MLS versions.
    let _default_extraced = default_secret.hkdf_extract(&draft_secret);
}
