#![doc = include_str!("../README.md")]
//! ## Quick Start
//! For a quick start to learn how OpenMLS works here's the basic code to set
//! up to parties and have them create a group.
//!
//! ```
//! use openmls::prelude::*;
//! use openmls_rust_crypto::{OpenMlsRustCrypto};
//!
//! // Define cipher suite ...
//! let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//! // ... and the crypto backend to use.
//! let backend = &OpenMlsRustCrypto::default();
//!
//! // Now let's create two participants.
//!
//! // A helper to create and store credentials.
//! fn generate_credential_bundle(
//!     identity: Vec<u8>,
//!     credential_type: CredentialType,
//!     signature_algorithm: SignatureScheme,
//!     backend: &impl OpenMlsCryptoProvider,
//! ) -> Result<Credential, CredentialError> {
//!     let credential_bundle =
//!         CredentialBundle::new(identity, credential_type, signature_algorithm, backend)?;
//!     let credential_id =  credential_bundle.credential()
//!         .signature_key()
//!         .tls_serialize_detached()
//!         .expect("Error serializing signature key.");
//!     // Store the credential bundle into the key store so OpenMLS has access
//!     // to it.
//!     backend
//!         .key_store()
//!         .store(&credential_id, &credential_bundle)
//!         .expect("An unexpected error occurred.");
//!     Ok(credential_bundle.into_parts().0)
//! }
//!
//! // A helper to create key package bundles.
//! fn generate_key_package_bundle(
//!     ciphersuites: &[Ciphersuite],
//!     credential: &Credential,
//!     backend: &impl OpenMlsCryptoProvider,
//! ) -> Result<KeyPackage, KeyPackageBundleNewError> {
//!     // Fetch the credential bundle from the key store
//!     let credential_id = credential
//!         .signature_key()
//!         .tls_serialize_detached()
//!         .expect("Error serializing signature key.");
//!     let credential_bundle = backend
//!         .key_store()
//!         .read(&credential_id)
//!         .expect("An unexpected error occurred.");
//!
//!     // Create the key package bundle
//!     let key_package_bundle =
//!         KeyPackageBundle::new(ciphersuites, &credential_bundle, backend, vec![])?;
//!
//!     // Store it in the key store
//!     let key_package_id = key_package_bundle.key_package()
//!             .hash_ref(backend.crypto())
//!             .expect("Could not hash KeyPackage.");
//!     backend
//!         .key_store()
//!         .store(key_package_id.value(), &key_package_bundle)
//!         .expect("An unexpected error occurred.");
//!     Ok(key_package_bundle.into_parts().0)
//! }
//!
//! // First they need credentials to identify them
//! let sasha_credential = generate_credential_bundle(
//!     "Sasha".into(),
//!     CredentialType::Basic,
//!     ciphersuite.signature_algorithm(),
//!     backend,
//! )
//! .expect("An unexpected error occurred.");
//!
//! let maxim_credential = generate_credential_bundle(
//!     "Maxim".into(),
//!     CredentialType::Basic,
//!     ciphersuite.signature_algorithm(),
//!     backend,
//! )
//! .expect("An unexpected error occurred.");
//!
//! // Then they generate key packages to facilitate the asynchronous handshakes
//! // in MLS
//!
//! // Generate KeyPackages
//! let sasha_key_package = generate_key_package_bundle(&[ciphersuite], &sasha_credential, backend)
//!     .expect("An unexpected error occurred.");
//!
//! let maxim_key_package = generate_key_package_bundle(&[ciphersuite], &maxim_credential, backend)
//!     .expect("An unexpected error occurred.");
//!
//! // Now Sasha starts a new group ...
//! let mut sasha_group = MlsGroup::new(
//!     backend,
//!     &MlsGroupConfig::default(),
//!     GroupId::from_slice(b"My First Group"),
//!     sasha_key_package
//!         .hash_ref(backend.crypto())
//!         .expect("Could not hash KeyPackage.")
//!         .as_slice(),
//! )
//! .expect("An unexpected error occurred.");
//!
//! // ... and invites Maxim.
//! // The key package has to be retrieved from Maxim in some way. Most likely
//! // via a server storing key packages for users.
//! let (mls_message_out, welcome) = sasha_group
//!     .add_members(backend, &[maxim_key_package])
//!     .expect("Could not add members.");
//!
//! // Sasha merges the pending commit that adds Maxim.
//! sasha_group
//!    .merge_pending_commit()
//!    .expect("error merging pending commit");
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
pub mod credentials;
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
mod key_store;
mod tree;

/// Single place, re-exporting the most used public functions.
pub mod prelude;
