//! # Key package tests
//!

use maelstrom::{
    ciphersuite::{Ciphersuite, CiphersuiteName},
    config::Config,
    creds::*,
    extensions::*,
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
            let id = vec![1, 2, 3];
            let credential_bundle =
                CredentialBundle::new(id, CredentialType::Basic, ciphersuite.get_name()).unwrap();
            let kpb = KeyPackageBundle::new(ciphersuite.get_name(), &credential_bundle, Vec::new());

            let extensions = kpb.get_key_package().get_extensions_ref();

            // The capabilities extension must be present and valid.
            // It's added automatically.
            let capabilities_extension = extensions
                .iter()
                .find(|e| e.get_type() == ExtensionType::Capabilities)
                .expect("Capabilities extension is missing in key package");
            let _capabilities_extension = capabilities_extension
                .to_capabilities_extension_ref()
                .unwrap();
            // TODO: #101 test capabilities.

            // Lifetime extension must be present and valid.
            // TODO: #99 add lifetime extension to key packages
            // let lifetime_extension = extensions
            //     .iter()
            //     .find(|e| e.get_type() == ExtensionType::Lifetime)
            //     .expect("Lifetime extension is missing in key package");

            // Parent hash extension must be present and valid.
            // TODO: #100 add parent hash extension to key package
            // let parent_hash_extension = extensions
            //     .iter()
            //     .find(|e| e.get_type() == ExtensionType::ParentHash)
            //     .expect("Parent hash extension is missing in key package");
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
