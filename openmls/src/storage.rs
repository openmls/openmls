//! OpenMLS Storage
//!
//! This module serves two purposes:
//!
//! - It implements the Key, Entity and type traits from `openmls_traits::storage::traits`.
//! - It defines traits that specialize the Storage and Provider traits from `openmls_traits`.
//!   This way, the Rust compiler knows that the concrete types match when we use the Provider in
//!   the code.

use openmls_traits::storage::{traits, Entity, Key, CURRENT_VERSION};

use crate::binary_tree::LeafNodeIndex;
use crate::group::proposal_store::QueuedProposal;
use crate::group::{MlsGroupJoinConfig, MlsGroupState};
use crate::{
    ciphersuite::hash_ref::ProposalRef,
    group::{GroupContext, GroupId, InterimTranscriptHash},
    messages::ConfirmationTag,
    treesync::{LeafNode, TreeSync},
};
use crate::{
    group::{past_secrets::MessageSecretsStore, GroupEpoch},
    prelude::KeyPackageBundle,
    schedule::{
        psk::{store::ResumptionPskStore, PskBundle},
        GroupEpochSecrets, Psk,
    },
    treesync::{node::encryption_keys::EncryptionKeyPair, EncryptionKey},
};

#[cfg(test)]
pub mod kat_storage_stability;

/// A convenience trait for the current version of the storage.
/// Throughout the code, this one should be used instead of `openmls_traits::storage::StorageProvider`.
pub trait StorageProvider: openmls_traits::storage::StorageProvider<CURRENT_VERSION> {}

/// A convenience trait for the current version of the public storage.
/// Throughout the code, this one should be used instead of `openmls_traits::public_storage::PublicStorageProvider`.
pub trait PublicStorageProvider:
    openmls_traits::public_storage::PublicStorageProvider<
    CURRENT_VERSION,
    PublicError = <Self as PublicStorageProvider>::Error,
>
{
    /// An opaque error returned by all methods on this trait.
    /// Matches `PublicError` from `openmls_traits::storage::PublicStorageProvider`.
    type Error: core::fmt::Debug + std::error::Error;
}

impl<P: openmls_traits::storage::StorageProvider<CURRENT_VERSION>> StorageProvider for P {}

impl<P: openmls_traits::public_storage::PublicStorageProvider<CURRENT_VERSION>>
    PublicStorageProvider for P
{
    type Error = P::PublicError;
}

/// A convenience trait for the OpenMLS provider that defines the storage provider
/// for the current version of storage.
/// Throughout the code, this one should be used instead of `openmls_traits::OpenMlsProvider`.
pub trait OpenMlsProvider:
    openmls_traits::OpenMlsProvider<StorageProvider = Self::Storage>
{
    /// The storage to use
    type Storage: StorageProvider<Error = Self::StorageError>;
    /// The storage error type
    type StorageError: std::error::Error;
}

impl<
        Error: std::error::Error,
        SP: StorageProvider<Error = Error>,
        OP: openmls_traits::OpenMlsProvider<StorageProvider = SP>,
    > OpenMlsProvider for OP
{
    type Storage = SP;
    type StorageError = Error;
}

// Implementations for the Entity and Key traits

impl Entity<CURRENT_VERSION> for QueuedProposal {}
impl traits::QueuedProposal<CURRENT_VERSION> for QueuedProposal {}

impl Entity<CURRENT_VERSION> for TreeSync {}
impl traits::TreeSync<CURRENT_VERSION> for TreeSync {}

impl Key<CURRENT_VERSION> for GroupId {}
impl traits::GroupId<CURRENT_VERSION> for GroupId {}

impl Key<CURRENT_VERSION> for ProposalRef {}
impl Entity<CURRENT_VERSION> for ProposalRef {}
impl traits::ProposalRef<CURRENT_VERSION> for ProposalRef {}
impl traits::HashReference<CURRENT_VERSION> for ProposalRef {}

impl Entity<CURRENT_VERSION> for GroupContext {}
impl traits::GroupContext<CURRENT_VERSION> for GroupContext {}

impl Entity<CURRENT_VERSION> for InterimTranscriptHash {}
impl traits::InterimTranscriptHash<CURRENT_VERSION> for InterimTranscriptHash {}

impl Entity<CURRENT_VERSION> for ConfirmationTag {}
impl traits::ConfirmationTag<CURRENT_VERSION> for ConfirmationTag {}

impl Entity<CURRENT_VERSION> for KeyPackageBundle {}
impl traits::KeyPackage<CURRENT_VERSION> for KeyPackageBundle {}

impl Key<CURRENT_VERSION> for EncryptionKey {}
impl traits::EncryptionKey<CURRENT_VERSION> for EncryptionKey {}

impl Entity<CURRENT_VERSION> for EncryptionKeyPair {}
impl traits::HpkeKeyPair<CURRENT_VERSION> for EncryptionKeyPair {}

impl Entity<CURRENT_VERSION> for LeafNodeIndex {}
impl traits::LeafNodeIndex<CURRENT_VERSION> for LeafNodeIndex {}

impl Entity<CURRENT_VERSION> for GroupEpochSecrets {}
impl traits::GroupEpochSecrets<CURRENT_VERSION> for GroupEpochSecrets {}

impl Entity<CURRENT_VERSION> for MessageSecretsStore {}
impl traits::MessageSecrets<CURRENT_VERSION> for MessageSecretsStore {}

impl Entity<CURRENT_VERSION> for ResumptionPskStore {}
impl traits::ResumptionPskStore<CURRENT_VERSION> for ResumptionPskStore {}

impl Entity<CURRENT_VERSION> for MlsGroupJoinConfig {}
impl traits::MlsGroupJoinConfig<CURRENT_VERSION> for MlsGroupJoinConfig {}

impl Entity<CURRENT_VERSION> for MlsGroupState {}
impl traits::GroupState<CURRENT_VERSION> for MlsGroupState {}

impl Entity<CURRENT_VERSION> for LeafNode {}
impl traits::LeafNode<CURRENT_VERSION> for LeafNode {}

// Crypto

impl Key<CURRENT_VERSION> for GroupEpoch {}
impl traits::EpochKey<CURRENT_VERSION> for GroupEpoch {}

impl Key<CURRENT_VERSION> for Psk {}
impl traits::PskId<CURRENT_VERSION> for Psk {}

impl Entity<CURRENT_VERSION> for PskBundle {}
impl traits::PskBundle<CURRENT_VERSION> for PskBundle {}

#[cfg(test)]
mod test {
    use crate::{
        group::mls_group::tests_and_kats::utils::setup_client, prelude::KeyPackageBuilder,
    };

    use super::*;

    use openmls_rust_crypto::{MemoryStorage, OpenMlsRustCrypto};
    use openmls_traits::{
        storage::{traits as type_traits, StorageProvider, V_TEST},
        types::{Ciphersuite, HpkePrivateKey},
        OpenMlsProvider,
    };
    use serde::{Deserialize, Serialize};

    // Test upgrade path
    // Assume we have a new key package bundle representation.
    #[derive(Serialize, Deserialize)]
    struct NewKeyPackageBundle {
        ciphersuite: Ciphersuite,
        key_package: crate::key_packages::KeyPackage,
        private_init_key: HpkePrivateKey,
        private_encryption_key: crate::treesync::node::encryption_keys::EncryptionPrivateKey,
    }

    impl Entity<V_TEST> for NewKeyPackageBundle {}
    impl type_traits::KeyPackage<V_TEST> for NewKeyPackageBundle {}

    impl Key<V_TEST> for EncryptionKey {}
    impl type_traits::EncryptionKey<V_TEST> for EncryptionKey {}

    impl Entity<V_TEST> for EncryptionKeyPair {}
    impl type_traits::HpkeKeyPair<V_TEST> for EncryptionKeyPair {}

    impl Key<V_TEST> for ProposalRef {}
    impl type_traits::HashReference<V_TEST> for ProposalRef {}

    #[test]
    fn key_packages_key_upgrade() {
        // Store an old version
        let provider = OpenMlsRustCrypto::default();

        let (credential_with_key, _kpb, signer, _pk) = setup_client(
            "Alice",
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            &provider,
        );

        // build and store key package bundle
        let key_package_bundle = KeyPackageBuilder::new()
            .build(
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                &provider,
                &signer,
                credential_with_key,
            )
            .unwrap();

        let key_package = key_package_bundle.key_package();
        let key_package_ref = key_package.hash_ref(provider.crypto()).unwrap();

        // TODO #1566: Serialize the old storage. This should become a kat test file

        // ---- migration starts here ----
        let new_storage_provider = MemoryStorage::default();

        // first, read the old data
        let read_key_package_bundle: crate::prelude::KeyPackageBundle =
            <MemoryStorage as StorageProvider<CURRENT_VERSION>>::key_package(
                provider.storage(),
                &key_package_ref,
            )
            .unwrap()
            .unwrap();

        // then, build the new data from the old data
        let new_key_package_bundle = NewKeyPackageBundle {
            ciphersuite: read_key_package_bundle.key_package().ciphersuite(),
            key_package: read_key_package_bundle.key_package().clone(),
            private_init_key: read_key_package_bundle.init_private_key().clone(),
            private_encryption_key: read_key_package_bundle.private_encryption_key.clone(),
        };

        // insert the data in the new format
        <MemoryStorage as StorageProvider<V_TEST>>::write_key_package(
            &new_storage_provider,
            &key_package_ref,
            &new_key_package_bundle,
        )
        .unwrap();

        // read the new value from storage
        let read_new_key_package_bundle: NewKeyPackageBundle =
            <MemoryStorage as StorageProvider<V_TEST>>::key_package(
                &new_storage_provider,
                &key_package_ref,
            )
            .unwrap()
            .unwrap();

        // compare it to the old_storage

        assert_eq!(
            &read_new_key_package_bundle.key_package,
            key_package_bundle.key_package()
        );
        assert_eq!(
            read_new_key_package_bundle.ciphersuite,
            key_package_bundle.key_package().ciphersuite()
        );
        assert_eq!(
            &read_new_key_package_bundle.private_encryption_key,
            &key_package_bundle.private_encryption_key
        );
        assert_eq!(
            &read_new_key_package_bundle.private_init_key,
            &key_package_bundle.private_init_key
        );
    }
}
