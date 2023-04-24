//! Test utilities
#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
    fmt::Write as FmtWrite,
    fs::File,
    io::{BufReader, Write},
};

use openmls_basic_credential::OpenMlsBasicCredential;
use openmls_traits::{
    key_store::OpenMlsKeyStore,
    types::{HpkeKeyPair, SignatureScheme},
};
pub use openmls_traits::{types::Ciphersuite, OpenMlsCryptoProvider};
pub use rstest::*;
pub use rstest_reuse::{self, *};
use serde::{self, de::DeserializeOwned, Serialize};

pub use crate::utils::*;
use crate::{
    ciphersuite::{HpkePrivateKey, OpenMlsSignaturePublicKey},
    extensions::Extensions,
    key_packages::KeyPackage,
    prelude::{CryptoConfig, KeyPackageBuilder},
    treesync::node::encryption_keys::{EncryptionKeyPair, EncryptionPrivateKey},
    versions::ProtocolVersion,
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

/// Helper function to generate and store a Credential
pub fn credential(
    identity: &[u8],
    signature_scheme: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> OpenMlsBasicCredential {
    let credential = OpenMlsBasicCredential::new(signature_scheme, identity.to_vec()).unwrap();
    credential.store(backend.key_store()).unwrap();
    credential
}

/// Generate a key package with extensions
pub fn key_package_with_extensions<KeyStore: OpenMlsKeyStore>(
    backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    credential: &OpenMlsBasicCredential,
    ciphersuite: Ciphersuite,
    extensions: Extensions,
) -> KeyPackage {
    debug_assert!(ciphersuite.signature_algorithm() == credential.signature_scheme());
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
            backend,
            credential,
            credential,
        )
        .unwrap()
}

/// Generate a key package.
pub fn key_package<KeyStore: OpenMlsKeyStore>(
    backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
    credential: &OpenMlsBasicCredential,
    ciphersuite: Ciphersuite,
) -> KeyPackage {
    key_package_with_extensions(backend, credential, ciphersuite, Extensions::empty())
}

// === Convenience functions ===

#[cfg(test)]
pub(crate) struct GroupCandidate {
    pub identity: Vec<u8>,
    pub key_package: KeyPackage,
    pub encryption_keypair: EncryptionKeyPair,
    pub init_keypair: HpkeKeyPair,
    pub credential: OpenMlsBasicCredential,
}

#[cfg(test)]
pub(crate) fn generate_group_candidate(
    identity: &[u8],
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    use_store: bool,
) -> GroupCandidate {
    use openmls_traits::credential::OpenMlsCredential;

    let credential =
        OpenMlsBasicCredential::new(ciphersuite.signature_algorithm(), identity.to_vec()).unwrap();

    // Store if there is a key store.
    if use_store {
        credential.store(backend.key_store()).unwrap();
    }

    let (key_package, encryption_keypair, init_keypair) = {
        let builder = KeyPackageBuilder::new();

        if use_store {
            let key_package = builder
                .build(
                    CryptoConfig::with_default_version(ciphersuite),
                    backend,
                    &credential,
                    &credential,
                )
                .unwrap();

            let encryption_keypair = EncryptionKeyPair::read_from_key_store(
                backend,
                key_package.leaf_node().encryption_key(),
            )
            .unwrap();
            let init_keypair = {
                let private = backend
                    .key_store()
                    .read::<HpkePrivateKey>(key_package.hpke_init_key().as_slice())
                    .unwrap();

                HpkeKeyPair {
                    private: private.as_slice().to_vec(),
                    public: key_package.hpke_init_key().as_slice().to_vec(),
                }
            };

            (key_package, encryption_keypair, init_keypair)
        } else {
            // We don't want to store anything. So...
            let backend = OpenMlsRustCrypto::default();

            let key_package_creation_result = builder
                .build_without_key_storage(
                    CryptoConfig::with_default_version(ciphersuite),
                    &backend,
                    &credential,
                    &credential,
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
        credential,
    }
}

// === Define backend per platform ===

// For now we only use Evercrypt on specific platforms and only if the feature was enabled

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm"),
    feature = "evercrypt",
))]
pub use openmls_evercrypt::OpenMlsEvercrypt;
// This backend is currently used on all platforms
pub use openmls_rust_crypto::OpenMlsRustCrypto;

// === Backends ===

#[cfg(any(
    not(target_arch = "x86_64"),
    target_os = "macos",
    target_family = "wasm",
    not(feature = "evercrypt")
))]
#[template]
#[export]
#[rstest(backend,
    case::rust_crypto(&OpenMlsRustCrypto::default()),
  )
]
#[allow(non_snake_case)]
pub fn backends(backend: &impl OpenMlsCryptoProvider) {}

// For now we only use Evercrypt on specific platforms and only if the feature was enabled

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm"),
    feature = "evercrypt",
))]
#[template]
#[export]
#[rstest(backend,
    case::rust_crypto(&OpenMlsRustCrypto::default()),
    case::evercrypt(&openmls_evercrypt::OpenMlsEvercrypt::default()),
  )
]
#[allow(non_snake_case)]
pub fn backends(backend: &impl OpenMlsCryptoProvider) {}

// === Ciphersuites ===

// For now we support all ciphersuites, regardless of the backend

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
pub fn ciphersuites(ciphersuite: Ciphersuite) {}

// === Ciphersuites & backends ===

#[cfg(any(
    not(target_arch = "x86_64"),
    target_os = "macos",
    target_family = "wasm",
    not(feature = "evercrypt"),
))]
#[template]
#[export]
#[rstest(ciphersuite, backend,
    case::rust_crypto_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
  )
]
#[allow(non_snake_case)]
pub fn ciphersuites_and_backends(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {}

// For now we only use Evercrypt on specific platforms and only if the feature was enabled

#[cfg(all(
    target_arch = "x86_64",
    not(target_os = "macos"),
    not(target_family = "wasm"),
    feature = "evercrypt",
))]
#[template]
#[export]
#[rstest(ciphersuite, backend,
    case::rust_crypto_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &OpenMlsRustCrypto::default()),
    case::rust_crypto_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &OpenMlsRustCrypto::default()),
    case::evercrypt_MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, &openmls_evercrypt::OpenMlsEvercrypt::default()),
    case::evercrypt_MLS_128_DHKEMP256_AES128GCM_SHA256_P256(Ciphersuite::MLS_128_DHKEMP256_AES128GCM_SHA256_P256, &openmls_evercrypt::OpenMlsEvercrypt::default()),
    case::evercrypt_MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519(Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519, &openmls_evercrypt::OpenMlsEvercrypt::default()),
  )
]
#[allow(non_snake_case)]
pub fn ciphersuites_and_backends(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {}
