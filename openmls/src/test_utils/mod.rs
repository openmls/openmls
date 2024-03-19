//! Test utilities
#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
    fmt::Write as FmtWrite,
    fs::File,
    io::{BufReader, Write},
};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{key_store::OpenMlsKeyStore, types::HpkeKeyPair};
pub use openmls_traits::{types::Ciphersuite, OpenMlsProvider};
pub use rstest::*;
pub use rstest_reuse::{self, *};
use serde::{self, de::DeserializeOwned, Serialize};

#[cfg(test)]
use crate::group::tests::utils::CredentialWithKeyAndSigner;
pub use crate::utils::*;
use crate::{
    ciphersuite::{HpkePrivateKey, OpenMlsSignaturePublicKey},
    credentials::{Credential, CredentialType, CredentialWithKey},
    key_packages::KeyPackage,
    prelude::{CryptoConfig, KeyPackageBuilder},
    treesync::node::encryption_keys::{EncryptionKeyPair, EncryptionPrivateKey},
};

pub mod test_framework;

pub(crate) fn write(file_name: &str, obj: impl Serialize) {
    let mut file = match File::create(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {file_name}."),
    };
    file.write_all(
        serde_json::to_string_pretty(&obj)
            .expect("Error serializing test vectors")
            .as_bytes(),
    )
    .expect("Error writing test vector file");
}

// the macro is used in other files, suppress false positive
#[allow(unused_macros)]
macro_rules! read_json {
    ($file_name:expr) => {{
        let data = include_str!($file_name);
        serde_json::from_str(data).expect(&format!("Error reading file {}", $file_name))
    }};
}

pub(crate) fn read<T: DeserializeOwned>(file_name: &str) -> T {
    let file = match File::open(file_name) {
        Ok(f) => f,
        Err(_) => panic!("Couldn't open file {file_name}."),
    };
    let reader = BufReader::new(file);
    match serde_json::from_reader(reader) {
        Ok(r) => r,
        Err(e) => panic!("Error reading file.\n{e:?}"),
    }
}

/// Convert `bytes` to a hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::new();
    for &b in bytes {
        write!(&mut hex, "{b:02X}").expect("Unable to write to string");
    }
    hex
}

/// Convert a hex string to a byte vector.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0);
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        bytes.push(
            u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("An unexpected error occurred."),
        );
    }
    bytes
}

/// Convert a hex string to a byte vector.
/// If the input is `None`, this returns an empty vector.
pub fn hex_to_bytes_option(hex: Option<String>) -> Vec<u8> {
    match hex {
        Some(s) => hex_to_bytes(&s),
        None => vec![],
    }
}

// === Convenience functions ===

#[cfg(test)]
pub(crate) struct GroupCandidate {
    pub identity: Vec<u8>,
    pub key_package: KeyPackage,
    pub encryption_keypair: EncryptionKeyPair,
    pub init_keypair: HpkeKeyPair,
    pub signature_keypair: SignatureKeyPair,
    pub credential_with_key_and_signer: CredentialWithKeyAndSigner,
}

#[cfg(test)]
pub(crate) fn generate_group_candidate(
    identity: &[u8],
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    use_store: bool,
) -> GroupCandidate {
    use crate::credentials::BasicCredential;

    let credential_with_key_and_signer = {
        let credential = BasicCredential::new(identity.to_vec()).unwrap();

        let signature_keypair = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

        // Store if there is a key store.
        if use_store {
            signature_keypair.store(provider.key_store()).unwrap();
        }

        let signature_pkey = OpenMlsSignaturePublicKey::new(
            signature_keypair.to_public_vec().into(),
            ciphersuite.signature_algorithm(),
        )
        .unwrap();

        CredentialWithKeyAndSigner {
            credential_with_key: CredentialWithKey {
                credential: credential.into(),
                signature_key: signature_pkey.into(),
            },
            signer: signature_keypair,
        }
    };

    let (key_package, encryption_keypair, init_keypair) = {
        let builder = KeyPackageBuilder::new();

        if use_store {
            let key_package = builder
                .build(
                    CryptoConfig::with_default_version(ciphersuite),
                    provider,
                    &credential_with_key_and_signer.signer,
                    credential_with_key_and_signer.credential_with_key.clone(),
                )
                .unwrap();

            let encryption_keypair = EncryptionKeyPair::read_from_key_store(
                provider,
                key_package.leaf_node().encryption_key(),
            )
            .unwrap();
            let init_keypair = {
                let private = provider
                    .key_store()
                    .read::<HpkePrivateKey>(key_package.hpke_init_key().as_slice())
                    .unwrap();

                HpkeKeyPair {
                    private,
                    public: key_package.hpke_init_key().as_slice().to_vec(),
                }
            };

            (key_package, encryption_keypair, init_keypair)
        } else {
            // We don't want to store anything. So...
            let provider = OpenMlsRustCrypto::default();

            let key_package_creation_result = builder
                .build_without_key_storage(
                    CryptoConfig::with_default_version(ciphersuite),
                    &provider,
                    &credential_with_key_and_signer.signer,
                    credential_with_key_and_signer.credential_with_key.clone(),
                )
                .unwrap();

            let init_keypair = HpkeKeyPair {
                private: key_package_creation_result.init_private_key,
                public: key_package_creation_result
                    .key_package
                    .hpke_init_key()
                    .as_slice()
                    .to_vec(),
            };

            (
                key_package_creation_result.key_package,
                key_package_creation_result.encryption_keypair,
                init_keypair,
            )
        }
    };

    GroupCandidate {
        identity: identity.as_ref().to_vec(),
        key_package,
        encryption_keypair,
        init_keypair,
        signature_keypair: credential_with_key_and_signer.signer.clone(),
        credential_with_key_and_signer,
    }
}

// === Define provider per platform ===

// This provider is currently used on all platforms
#[cfg(feature = "libcrux-provider")]
pub use openmls_libcrux_crypto::Provider as OpenMlsLibcrux;
pub use openmls_rust_crypto::OpenMlsRustCrypto;

// === providers ===

#[template]
#[export]
#[cfg_attr(feature = "libcrux-provider", rstest(provider,
    case::rust_crypto(&OpenMlsRustCrypto::default()),
    case::libcrux(&OpenMlsLibcrux::default()),
  )
)]
#[cfg_attr(not(feature = "libcrux-provider"),rstest(provider,
    case::rust_crypto(&OpenMlsRustCrypto::default()),
  )
)]
#[allow(non_snake_case)]
#[cfg_attr(target_arch = "wasm32", openmls::wasm::test)]
pub fn providers(provider: &impl OpenMlsProvider) {}

// === Ciphersuites ===

// For now we support all ciphersuites, regardless of the provider

#[template]
#[export]
#[rstest(
    ciphersuite,
    case::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    ),
    case::MLS_128_DHKEMP256_AES128GCM_SHA256_P256(
        Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256
    ),
    case::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(
        Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
    )
)]
#[allow(non_snake_case)]
#[cfg_attr(target_arch = "wasm32", openmls::wasm::test)]
pub fn ciphersuites(ciphersuite: Ciphersuite) {}

// === Ciphersuites & providers ===

#[template]
#[export]
#[cfg_attr(feature = "libcrux-provider", rstest(ciphersuite, provider,
    case::rust_crypto_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::libcrux_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &$crate::test_utils::OpenMlsLibcrux::default()),
    case::libcrux_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &$crate::test_utils::OpenMlsLibcrux::default()),
    case::libcrux_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &$crate::test_utils::OpenMlsLibcrux::default()),
  )
)]
#[cfg_attr(not(feature = "libcrux-provider"),rstest(ciphersuite, provider,
    case::rust_crypto_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
  )
)]
#[allow(non_snake_case)]
#[cfg_attr(target_arch = "wasm32", openmls::wasm::test)]
pub fn ciphersuites_and_providers(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {}
