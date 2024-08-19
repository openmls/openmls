//! Test utilities
#![allow(dead_code)]
#![allow(unused_imports)]

use std::{
    fmt::Write as FmtWrite,
    fs::File,
    io::{BufReader, Write},
};

use openmls_basic_credential::SignatureKeyPair;
pub use openmls_traits::{
    storage::StorageProvider as StorageProviderTrait,
    types::{Ciphersuite, HpkeKeyPair},
    OpenMlsProvider,
};
use serde::{self, de::DeserializeOwned, Serialize};

#[cfg(test)]
use crate::group::tests_and_kats::utils::CredentialWithKeyAndSigner;
pub use crate::utils::*;
use crate::{
    ciphersuite::{HpkePrivateKey, OpenMlsSignaturePublicKey},
    credentials::{Credential, CredentialType, CredentialWithKey},
    key_packages::{KeyPackage, KeyPackageBuilder},
    prelude::KeyPackageBundle,
    treesync::node::encryption_keys::{EncryptionKeyPair, EncryptionPrivateKey},
};

pub mod frankenstein;
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
    pub key_package: KeyPackageBundle,
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
    use crate::{credentials::BasicCredential, prelude::KeyPackageBundle};

    let credential_with_key_and_signer = {
        let credential = BasicCredential::new(identity.to_vec());

        let signature_keypair = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

        // Store if there is a key store.
        if use_store {
            signature_keypair.store(provider.storage()).unwrap();
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

    let key_package = {
        let builder = KeyPackageBuilder::new();

        if use_store {
            builder
                .build(
                    ciphersuite,
                    provider,
                    &credential_with_key_and_signer.signer,
                    credential_with_key_and_signer.credential_with_key.clone(),
                )
                .unwrap()
        } else {
            // We don't want to store anything. So...
            let provider = OpenMlsRustCrypto::default();

            let key_package_creation_result = builder
                .build_without_storage(
                    ciphersuite,
                    &provider,
                    &credential_with_key_and_signer.signer,
                    credential_with_key_and_signer.credential_with_key.clone(),
                )
                .unwrap();

            KeyPackageBundle::new(
                key_package_creation_result.key_package,
                key_package_creation_result.init_private_key,
                key_package_creation_result
                    .encryption_keypair
                    .private_key()
                    .clone(),
            )
        }
    };

    GroupCandidate {
        identity: identity.as_ref().to_vec(),
        key_package,
        signature_keypair: credential_with_key_and_signer.signer.clone(),
        credential_with_key_and_signer,
    }
}

#[cfg(all(
    feature = "libcrux-provider",
    not(any(
        target_arch = "wasm32",
        all(target_arch = "x86", target_os = "windows")
    ))
))]
pub type OpenMlsLibcrux = openmls_libcrux_crypto::Provider;
pub type OpenMlsRustCrypto = openmls_rust_crypto::OpenMlsRustCrypto;
