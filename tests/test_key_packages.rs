//! # Key package tests
//!

use maelstrom::{
    ciphersuite::{Ciphersuite, CiphersuiteName},
    config::Config,
    creds::*,
    key_packages::*,
};

macro_rules! key_package_generation {
    ($name:ident, $ciphersuite:expr, $supported:literal) => {
        #[test]
        fn $name() {
            if !$supported {
                // TODO: enable more testing for unsupported ciphersuites when they return errors.
                return;
            }
            let ciphersuite = Ciphersuite::new($ciphersuite);
            let supported_ciphersuites = Config::supported_ciphersuites();
            assert_eq!($supported, supported_ciphersuites.contains(&$ciphersuite));
            let signature_keypair = ciphersuite.new_signature_keypair();
            let identity =
                Identity::new_with_keypair(ciphersuite, vec![1, 2, 3], signature_keypair.clone());
            let credential = Credential::Basic(BasicCredential::from(&identity));
            let kpb = KeyPackageBundle::new(
                &ciphersuite,
                signature_keypair.get_private_key(),
                credential,
                None,
            );
        }
    };
}

key_package_generation!(
    key_package_0x0001,
    CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    true
);
key_package_generation!(
    key_package_0x0002,
    CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
    true
);
key_package_generation!(
    key_package_0x0003,
    CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    true
);
key_package_generation!(
    key_package_0x0004,
    CiphersuiteName::MLS10_256_DHKEMX448_AES256GCM_SHA512_Ed448,
    false
);
key_package_generation!(
    key_package_0x0005,
    CiphersuiteName::MLS10_256_DHKEMP521_AES256GCM_SHA512_P521,
    false
);
key_package_generation!(
    key_package_0x0006,
    CiphersuiteName::MLS10_256_DHKEMX448_CHACHA20POLY1305_SHA512_Ed448,
    false
);
