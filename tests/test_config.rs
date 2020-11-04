//! # Test configuration
//!
//! openmls can be configured globally to define
//! * which MLS protocol versions are supported
//! * which ciphersuites are supported
//! * which extensions are supported
//!

use openmls::prelude::*;

#[test]
fn protocol_version() {
    let mls10_version = ProtocolVersion::Mls10;
    let default_version = ProtocolVersion::default();

    // The encoding of the protocol version is the version as u8.
    let mls10_encoded = mls10_version.encode_detached().unwrap();
    assert_eq!(1, mls10_encoded.len());
    assert_eq!(mls10_encoded[0], mls10_version as u8);

    let default_encoded = default_version.encode_detached().unwrap();
    assert_eq!(1, default_encoded.len());
    assert_eq!(default_encoded[0], default_version as u8);

    // Default and MLS1.0 versions have to be 1.
    assert_eq!(1, mls10_encoded[0]);
    assert_eq!(1, default_encoded[0]);

    // Make sure the supported protocol versions are what we expect them to be.
    let supported_versions = Config::supported_versions();
    assert_eq!(vec![ProtocolVersion::Mls10], supported_versions);
}

#[test]
fn default_extensions() {
    // Make sure the supported extensions are what we expect them to be.
    let supported_extensions = Config::supported_extensions();
    assert_eq!(
        vec![
            ExtensionType::Capabilities,
            ExtensionType::Lifetime,
            ExtensionType::KeyID
        ],
        supported_extensions
    );
}

#[test]
fn default_ciphersuites() {
    // Make sure the supported ciphersuites are what we expect them to be.
    let supported_ciphersuites = Config::supported_ciphersuite_names();
    assert_eq!(
        vec![
            CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256
        ],
        supported_ciphersuites
    );
}
