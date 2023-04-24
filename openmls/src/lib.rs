#![doc = include_str!("../README.md")]
//! ## Quick Start
//! For a quick start to learn how OpenMLS works here's the basic code to set
//! up to parties and have them create a group.
//!
//! ```
//! use openmls::prelude::{*, config::CryptoConfig};
//! use openmls_rust_crypto::{OpenMlsRustCrypto};
//! use openmls_basic_credential::OpenMlsBasicCredential;
//!
//! // Define ciphersuite ...
//! let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//! // ... and the crypto backend to use.
//! let backend = &OpenMlsRustCrypto::default();
//!
//! // Now let's create two participants.
//!
//! // A helper to create and store credentials.
//! fn generate_credential(
//!     identity: Vec<u8>,
//!     signature_algorithm: SignatureScheme,
//!     backend: &impl OpenMlsCryptoProvider,
//! ) -> OpenMlsBasicCredential {
//!     let credential =
//!         OpenMlsBasicCredential::new(signature_algorithm, identity)
//!             .expect("Error generating a signature key pair.");
//!
//!     // Store the credential bundle into the key store so OpenMLS has access
//!     // to it.
//!     credential
//!         .store(backend.key_store())
//!         .expect("Error storing signature keys in key store.");
//!     
//!     credential
//! }
//!
//! // A helper to create key package bundles.
//! fn generate_key_package(
//!     ciphersuite: Ciphersuite,
//!     backend: &impl OpenMlsCryptoProvider,
//!     signer: &OpenMlsBasicCredential,
//!     credential_with_key: &OpenMlsBasicCredential,
//! ) -> KeyPackage {
//!     // Create the key package
//!     KeyPackage::builder()
//!         .build(
//!             CryptoConfig {
//!                 ciphersuite,
//!                 version: ProtocolVersion::default(),
//!             },
//!             backend,
//!             signer,
//!             credential_with_key,
//!         )
//!         .unwrap()
//! }
//!
//! // First they need credentials to identify them
//! let sasha_credential = generate_credential(
//!     "Sasha".into(),
//!     ciphersuite.signature_algorithm(),
//!     backend,
//! );
//!
//! let maxim_credential = generate_credential(
//!     "Maxim".into(),
//!     ciphersuite.signature_algorithm(),
//!     backend,
//! );
//!
//! // Then they generate key packages to facilitate the asynchronous handshakes
//! // in MLS
//!
//! // Generate KeyPackages
//! let maxim_key_package = generate_key_package(ciphersuite, backend, &maxim_credential, &maxim_credential);
//!
//! // Now Sasha starts a new group ...
//! let mut sasha_group = MlsGroup::new(
//!     backend,
//!     &sasha_credential,
//!     &MlsGroupConfig::default(),
//!     &sasha_credential,
//! )
//! .expect("An unexpected error occurred.");
//!
//! // ... and invites Maxim.
//! // The key package has to be retrieved from Maxim in some way. Most likely
//! // via a server storing key packages for users.
//! let (mls_message_out, welcome_out, group_info) = sasha_group
//!     .add_members(backend, &sasha_credential, &[maxim_key_package])
//!     .expect("Could not add members.");
//!
//! // Sasha merges the pending commit that adds Maxim.
//! sasha_group
//!    .merge_pending_commit(backend)
//!    .expect("error merging pending commit");
//!
//! // Sascha serializes the [`MlsMessageOut`] containing the [`Welcome`].
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
//!    MlsMessageInBody::Welcome(welcome) => welcome,
//!    // We know it's a welcome message, so we ignore all other cases.
//!    _ => unreachable!("Unexpected message type."),
//! };
//!
//! // Now Maxim can join the group.
//!  let mut maxim_group = MlsGroup::new_from_welcome(
//!     backend,
//!     &MlsGroupConfig::default(),
//!     welcome,
//!     // The public tree is need and transferred out of band.
//!     // It is also possible to use the [`RatchetTreeExtension`]
//!     Some(sasha_group.export_ratchet_tree()),
//!  )
//!  .expect("Error joining group from Welcome");
//! ```
//!
//! [//]: # "links and badges"
//! [user Manual]: https://openmls.tech/book
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(not(feature = "test-utils"), deny(missing_docs))]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![cfg(any(
    target_pointer_width = "32",
    target_pointer_width = "64",
    target_pointer_width = "128"
))]

// === Testing ===

/// Single place, re-exporting all structs and functions needed for integration tests
#[cfg(any(feature = "test-utils", test))]
pub mod prelude_test;

#[cfg(any(feature = "test-utils", test))]
pub use rstest_reuse;

#[cfg(any(feature = "test-utils", test))]
#[macro_use]
pub mod test_utils;

// === Modules ===

#[macro_use]
mod utils;

pub mod error;

// Public
pub mod ciphersuite;
pub mod extensions;
pub mod framing;
pub mod group;
pub mod key_packages;
pub mod messages;
pub mod schedule;
pub mod treesync;
pub mod versions;

// Private
mod binary_tree;
mod tree;

/// Single place, re-exporting the most used public functions.
pub mod prelude;
