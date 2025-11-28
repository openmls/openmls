#![doc = include_str!("../README.md")]
//! ## Quick Start
//! For a quick start to learn how OpenMLS works here's the basic code to set
//! up to parties and have them create a group.
//!
//! ```
//! use openmls::{prelude::{*,  tls_codec::*}};
//! use openmls_rust_crypto::{OpenMlsRustCrypto};
//! use openmls_basic_credential::SignatureKeyPair;
//!
//! // Define ciphersuite ...
//! let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//! // ... and the crypto provider to use.
//! let provider = &OpenMlsRustCrypto::default();
//!
//! // Now let's create two participants.
//!
//! // A helper to create and store credentials.
//! fn generate_credential_with_key(
//!     identity: Vec<u8>,
//!     credential_type: CredentialType,
//!     signature_algorithm: SignatureScheme,
//!     provider: &impl OpenMlsProvider,
//! ) -> (CredentialWithKey, SignatureKeyPair) {
//!     let credential = BasicCredential::new(identity);
//!     let signature_keys =
//!         SignatureKeyPair::new(signature_algorithm)
//!             .expect("Error generating a signature key pair.");
//!
//!     // Store the signature key into the key store so OpenMLS has access
//!     // to it.
//!     signature_keys
//!         .store(provider.storage())
//!         .expect("Error storing signature keys in key store.");
//!
//!     (
//!         CredentialWithKey {
//!             credential: credential.into(),
//!             signature_key: signature_keys.public().into(),
//!         },
//!         signature_keys,
//!     )
//! }
//!
//! // A helper to create key package bundles.
//! fn generate_key_package(
//!     ciphersuite: Ciphersuite,
//!     provider: &impl OpenMlsProvider,
//!     signer: &SignatureKeyPair,
//!     credential_with_key: CredentialWithKey,
//! ) -> KeyPackageBundle {
//!     // Create the key package
//!     KeyPackage::builder()
//!         .build(
//!             ciphersuite,
//!             provider,
//!             signer,
//!             credential_with_key,
//!         )
//!         .unwrap()
//! }
//!
//! // First they need credentials to identify them
//! let (sasha_credential_with_key, sasha_signer) = generate_credential_with_key(
//!     "Sasha".into(),
//!     CredentialType::Basic,
//!     ciphersuite.signature_algorithm(),
//!     provider,
//! );
//!
//! let (maxim_credential_with_key, maxim_signer) = generate_credential_with_key(
//!     "Maxim".into(),
//!     CredentialType::Basic,
//!     ciphersuite.signature_algorithm(),
//!     provider,
//! );
//!
//! // Then they generate key packages to facilitate the asynchronous handshakes
//! // in MLS
//!
//! // Generate KeyPackages
//! let maxim_key_package = generate_key_package(ciphersuite, provider, &maxim_signer, maxim_credential_with_key);
//!
//! // Now Sasha starts a new group ...
//! let mut sasha_group = MlsGroup::new(
//!     provider,
//!     &sasha_signer,
//!     &MlsGroupCreateConfig::default(),
//!     sasha_credential_with_key,
//! )
//! .expect("An unexpected error occurred.");
//!
//! // ... and invites Maxim.
//! // The key package has to be retrieved from Maxim in some way. Most likely
//! // via a server storing key packages for users.
//! let (mls_message_out, welcome_out, group_info) = sasha_group
//!     .add_members(provider, &sasha_signer, core::slice::from_ref(maxim_key_package.key_package()))
//!     .expect("Could not add members.");
//!
//! // Sasha merges the pending commit that adds Maxim.
//! sasha_group
//!    .merge_pending_commit(provider)
//!    .expect("error merging pending commit");
//!
//! // Sasha serializes the [`MlsMessageOut`] containing the [`Welcome`].
//! let serialized_welcome = welcome_out
//!    .tls_serialize_detached()
//!    .expect("Error serializing welcome");
//!
//! // Maxim can now de-serialize the message as an [`MlsMessageIn`] ...
//! let mls_message_in = MlsMessageIn::tls_deserialize(&mut serialized_welcome.as_slice())
//!    .expect("An unexpected error occurred.");
//!
//! // ... and inspect the message.
//! let welcome = match mls_message_in.extract() {
//!    MlsMessageBodyIn::Welcome(welcome) => welcome,
//!    // We know it's a welcome message, so we ignore all other cases.
//!    _ => unreachable!("Unexpected message type."),
//! };
//!
//! // Now Maxim can build a staged join for the group in order to inspect the welcome
//! let maxim_staged_join = StagedWelcome::new_from_welcome(
//!     provider,
//!     &MlsGroupJoinConfig::default(),
//!     welcome,
//!     // The public tree is needed and transferred out of band.
//!     // It is also possible to use the [`RatchetTreeExtension`]
//!     Some(sasha_group.export_ratchet_tree().into()),
//! )
//! .expect("Error creating a staged join from Welcome");
//!
//! // Finally, Maxim can create the group
//! let mut maxim_group = maxim_staged_join
//!     .into_group(provider)
//!     .expect("Error creating the group from the staged join");
//! ```
//!
//! [//]: # "links and badges"
//! [user Manual]: https://book.openmls.tech
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(not(feature = "test-utils"), deny(missing_docs))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![cfg(any(target_pointer_width = "32", target_pointer_width = "64",))]

#[cfg(all(target_arch = "wasm32", not(feature = "js")))]
compile_error!("In order for OpenMLS to build for WebAssembly, JavaScript APIs must be available (for access to secure randomness and the current time). This can be signalled by setting the `js` feature on OpenMLS.");

// === Testing ===

/// Single place, re-exporting all structs and functions needed for integration tests
#[cfg(any(feature = "test-utils", test))]
pub mod prelude_test;

#[cfg(any(feature = "test-utils", test))]
#[macro_use]
pub mod test_utils;

#[cfg(test)]
pub mod kat_vl;

// === Modules ===

#[macro_use]
mod utils;

pub mod error;

// Public
pub mod ciphersuite;
#[cfg(feature = "extensions-draft-08")]
pub mod component;
pub mod credentials;
pub mod extensions;
pub mod framing;
pub mod grease;
pub mod group;
pub mod key_packages;
pub mod messages;
pub mod schedule;
pub mod treesync;
pub mod versions;

// implement storage traits
// public
pub mod storage;

// Private
mod binary_tree;
mod skip_validation;
mod tree;

/// Single place, re-exporting the most used public functions.
pub mod prelude;

// this is a workaround, see https://github.com/la10736/rstest/issues/211#issuecomment-1701238125
#[cfg(any(test, feature = "test-utils"))]
pub mod wasm {
    pub use wasm_bindgen_test::wasm_bindgen_test as test;
}
