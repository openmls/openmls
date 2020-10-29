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
                CredentialBundle::new(id, CredentialType::Basic, ciphersuite.name()).unwrap();
            let mut kpb = KeyPackageBundle::new(
                ciphersuite.name(),
                &credential_bundle,
                Vec::new(),
                Some(&[$ciphersuite]),
            );

            // This key package is not valid because the lifetime extension is missing.
            assert!(kpb.get_key_package().verify().is_err());

            // Adding a lifetime extension.
            kpb.get_key_package_ref_mut()
                .add_extension(Box::new(LifetimeExtension::new(60)));

            // The key package is invalid because the signature is invalid now.
            assert!(kpb.get_key_package().verify().is_err());

            // After re-signing the package it is valid.
            kpb.get_key_package_ref_mut().sign(&credential_bundle);
            assert!(kpb.get_key_package().verify().is_ok());

            {
                let extensions = kpb.get_key_package().get_extensions_ref();

                // The capabilities extension must be present and valid.
                // It's added automatically.
                let capabilities_extension = extensions
                    .iter()
                    .find(|e| e.get_type() == ExtensionType::Capabilities)
                    .expect("Capabilities extension is missing in key package");
                let capabilities_extension = capabilities_extension
                    .to_capabilities_extension_ref()
                    .unwrap();

                // Only the single ciphersuite is set.
                assert_eq!(1, capabilities_extension.ciphersuites().len());
                assert_eq!($ciphersuite, capabilities_extension.ciphersuites()[0]);

                // Check supported versions.
                assert_eq!(
                    Config::supported_versions(),
                    capabilities_extension.versions()
                );

                // Check supported extensions.
                assert_eq!(
                    Config::supported_extensions(),
                    capabilities_extension.extensions()
                );

                // Get the lifetime extension. There's no public API for this but it
                // must be present.
                let lifetime_extension = extensions
                    .iter()
                    .find(|e| e.get_type() == ExtensionType::Lifetime)
                    .expect("Lifetime extension is missing in key package");
                let _lifetime_extension = lifetime_extension.to_lifetime_extension_ref().unwrap();
            }

            // Add and retrieve a key package ID.
            let key_id = [1, 2, 3, 4, 5, 6, 7];
            kpb.get_key_package_ref_mut()
                .add_extension(Box::new(KeyIDExtension::new(&key_id)));

            // The key package is invalid because the signature is invalid now.
            assert!(kpb.get_key_package().verify().is_err());

            // After re-signing the package it is valid.
            kpb.get_key_package_ref_mut().sign(&credential_bundle);
            assert!(kpb.get_key_package().verify().is_ok());

            // Get the key ID extension.
            let extensions = kpb.get_key_package().get_extensions_ref();
            let key_id_extension = extensions
                .iter()
                .find(|e| e.get_type() == ExtensionType::KeyID)
                .expect("Key ID extension is missing in key package");
            let key_id_extension = key_id_extension.to_key_id_extension_ref().unwrap();
            assert_eq!(&key_id, key_id_extension.as_slice());
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
