//! # OpenMLS
//!
//! OpenMLS is an implementation of the proposed [MLS protocol].
//!
//! The main entry point for most consumers should be the [MlsGroup](prelude::MlsGroup).
//! Please see the individual [modules](#modules) for more information.
//!
//! More information on how to use the library can be found in the [User Manual].
//!
//! ## Error handling
//!
//! Most function calls in the library return a `Result` and can therefore surface errors to the library consumer.
//! Errors can have different sources, depending on their nature. The following list explains the different error sources and how to handle them:
//!
//! ### Errors in dependencies
//!
//! The OpenMLS library relies on external dependencies for cryptographic primitives and storage of cryptographic key material. See the traits in the [User Manual] for more details on the dependencies.
//! When an unexpected error occurs in one of those dependencies, it is usually surfaced as a `LibraryError` to the consumer.
//!
//! ### Errors induced by wrong API use
//!
//! Whenever the caller calls an OpenMLS function with invalid input, an error is returned. Examples of wrong input can be: Adding a member twice to a group, interacting with an inactive group, removing inexistent
//! members from a group, etc. The precise error message depends on the function called, and the error will typically be an `enum` with explicit variants that state the reason for the error.
//! Consumers can branch on the variants of the `enum` and take action accordingly.
//!
//! ### Errors induced by processing invalid payload
//!
//! The library processes external payload in the form of messages sent over a network, or state loaded from disk. In both cases, multi-layered checks need to be done to make sure the payload
//! is syntactically and semantically correct. The syntax checks typically all happen at the serialization level and get detected early on. Semantic validation is more complex because data needs to be evaluated
//! in context. You can find more details about validation in the validation chapter of the [User Manual].
//! These errors are surfaced to the consumer at various stages of the processing, and the processing is aborted for the payload in question. Much like errors induced by wrong API usage, these errors are `enums` that
//! contain explicit variants for every error type. Consumers can branch on these variants to take action according to the specific error.
//!
//! ### Correctness errors in the library itself
//!
//! While the library has good test coverage in the form of unit & integration tests, theoretical correctness errors cannot be completely excluded. Should such an error occur, consumers will get
//! a `LibraryError` as a return value that contains backtraces indicating where in the code the error occurred and a short string for context. These details are important for debugging the library in such a case.
//! Consumers should save this information.
//!
//! All errors derive [`thiserror::Error`](https://docs.rs/thiserror/latest/thiserror/) as well as
//! [`Debug`](`std::fmt::Debug`), [`PartialEq`](`std::cmp::PartialEq`), and [`Clone`](`std::clone::Clone`).
//!
//! See the [mod@error] module for more details.
//!
//! ### Quick Start
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
//!     // let key_package = key_package_bundle.key_package().clone();
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
//! [mls protocol]: https://datatracker.ietf.org/doc/draft-ietf-mls-protocol/
//! [status]: https://img.shields.io/badge/status-pre_rfc-orange.svg?style=for-the-badge
//! [spec issues]: https://github.com/openmls/openmls/issues?q=is%3Aissue+is%3Aopen+label%3A%22mls-spec+change%22
//! [user Manual]: https://openmls.tech/book
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(test), forbid(unsafe_code))]
#![cfg_attr(not(feature = "test-utils"), warn(missing_docs))]

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

#[macro_use]
pub mod error;

// Public
pub mod ciphersuite;
pub mod credentials;
pub mod extensions;
pub mod framing;
pub mod group;
pub mod key_packages;
pub mod messages;
pub mod versions;

// Private
mod binary_tree;
mod key_store;
mod schedule;
mod tree;
mod treesync;

/// Single place, re-exporting the most used public functions.
pub mod prelude;

// Re-export types from Key Schedule
pub use crate::schedule::{AuthenticationSecret, ResumptionSecret};
