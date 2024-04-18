//! OpenMLS Storage
//!
//! TODO

use openmls_traits::storage::{traits, Entity, Key, CURRENT_VERSION};
use openmls_traits::types::HpkePrivateKey;
use serde::Deserialize;
use serde::Serialize;

use crate::binary_tree::LeafNodeIndex;
use crate::group::past_secrets::MessageSecretsStore;
use crate::group::GroupEpoch;
use crate::schedule::psk::store::ResumptionPskStore;
use crate::schedule::GroupEpochSecrets;
use crate::treesync::node::encryption_keys::EncryptionKeyPair;
use crate::treesync::EncryptionKey;
use crate::{
    ciphersuite::hash_ref::ProposalRef,
    group::{GroupContext, GroupId, InterimTranscriptHash, QueuedProposal},
    key_packages::KeyPackage,
    messages::ConfirmationTag,
    treesync::TreeSync,
};

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

impl Entity<CURRENT_VERSION> for KeyPackage {}
impl traits::KeyPackage<CURRENT_VERSION> for KeyPackage {}

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

// Crypto
#[derive(Serialize)]
pub(crate) struct StorageInitKey<'a>(pub(crate) &'a [u8]);
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct StorageHpkePrivateKey(pub(crate) HpkePrivateKey);

/// Helper to use slices as keys
#[derive(Serialize)]
pub(crate) struct StorageReference<'a>(pub(crate) &'a [u8]);

impl<'a> Key<CURRENT_VERSION> for StorageReference<'a> {}
impl<'a> traits::HashReference<CURRENT_VERSION> for StorageReference<'a> {}

impl core::fmt::Debug for StorageHpkePrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("StorageHpkePrivateKey")
            .field(&"***")
            .finish()
    }
}

impl<'a> Key<CURRENT_VERSION> for StorageInitKey<'a> {}
impl<'a> traits::InitKey<CURRENT_VERSION> for StorageInitKey<'a> {}

impl traits::HpkePrivateKey<CURRENT_VERSION> for StorageHpkePrivateKey {}
impl Entity<CURRENT_VERSION> for StorageHpkePrivateKey {}

impl Key<CURRENT_VERSION> for GroupEpoch {}
impl traits::EpochKey<CURRENT_VERSION> for GroupEpoch {}

/// A convenience trait for the current version of the storage.
pub trait StorageProvider: openmls_traits::storage::StorageProvider<CURRENT_VERSION> {}

impl<P: openmls_traits::storage::StorageProvider<CURRENT_VERSION>> StorageProvider for P {}

/// A convenience trait for the OpenMLS provider that defines the storage provider
/// for the current version of storage.
pub trait RefinedProvider:
    openmls_traits::OpenMlsProvider<StorageProvider = Self::Storage>
{
    /// The storage to use
    type Storage: StorageProvider<Error = Self::StorageError>;
    /// THe storage error type
    type StorageError: std::error::Error + PartialEq;
}

impl<
        Error: std::error::Error + PartialEq,
        SP: StorageProvider<Error = Error>,
        OP: openmls_traits::OpenMlsProvider<StorageProvider = SP>,
    > RefinedProvider for OP
{
    type Storage = SP;
    type StorageError = Error;
}

#[cfg(test)]
mod test {
    use crate::{
        group::test_core_group::setup_client,
        prelude::{InitKey, KeyPackageBuilder},
    };

    use super::*;

    use openmls_memory_keystore::MemoryKeyStore;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{
        crypto::OpenMlsCrypto,
        storage::{traits as type_traits, StorageProvider, V_TEST},
        types::Ciphersuite,
        OpenMlsProvider,
    };
    use tls_codec::Serialize;

    #[test]
    fn crypto() {
        let provider = OpenMlsRustCrypto::default();

        let key_pair = provider
            .crypto()
            .derive_hpke_keypair(
                Ciphersuite::hpke_config(
                    &Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                ),
                &[7; 32],
            )
            .unwrap();

        provider
            .storage()
            .write_init_private_key(
                &StorageInitKey(&key_pair.public),
                &StorageHpkePrivateKey(key_pair.private.clone()),
            )
            .unwrap();

        let private_key: StorageHpkePrivateKey = provider
            .storage()
            .init_private_key(&StorageInitKey(&key_pair.public))
            .unwrap()
            .unwrap();
        assert_eq!(private_key.0, key_pair.private);
    }

    // Test upgrade path
    // Assume we have a new init key representation.
    #[derive(Serialize, Deserialize)]
    struct NewStorageHpkePrivateKey {
        ciphersuite: Ciphersuite,
        key: HpkePrivateKey,
    }

    struct NewStorageKeyPackage {}

    impl type_traits::HpkePrivateKey<V_TEST> for NewStorageHpkePrivateKey {}
    impl Entity<V_TEST> for NewStorageHpkePrivateKey {}

    impl Entity<V_TEST> for KeyPackage {}
    impl type_traits::KeyPackage<V_TEST> for KeyPackage {}

    impl Key<V_TEST> for EncryptionKey {}
    impl type_traits::EncryptionKey<V_TEST> for EncryptionKey {}

    impl Entity<V_TEST> for EncryptionKeyPair {}
    impl type_traits::HpkeKeyPair<V_TEST> for EncryptionKeyPair {}

    impl Key<V_TEST> for InitKey {}
    impl type_traits::InitKey<V_TEST> for InitKey {}

    impl Key<V_TEST> for ProposalRef {}
    impl type_traits::HashReference<V_TEST> for ProposalRef {}

    #[test]
    fn init_key_upgrade() {
        // Store an old version
        let provider = OpenMlsRustCrypto::default();

        let (credential_with_key, _kpb, signer, _pk) = setup_client(
            "Alice",
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            &provider,
        );

        let key_package_bundle = KeyPackageBuilder::new()
            .build_without_key_storage(
                Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
                &provider,
                &signer,
                credential_with_key,
            )
            .unwrap();

        let (key_package, init_sk, encryption_keypair) = (
            key_package_bundle.key_package.clone(),
            StorageHpkePrivateKey(key_package_bundle.init_private_key.clone()),
            key_package_bundle.encryption_keypair.clone(),
        );

        let key_package_ref = crate::ciphersuite::hash_ref::make_key_package_ref(
            &key_package.tls_serialize_detached().unwrap(),
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
            provider.crypto(),
        )
        .unwrap();

        // write private keys
        <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::write_init_private_key(
            provider.storage(),
            &StorageInitKey(key_package.hpke_init_key().as_slice()),
            &init_sk,
        )
        .unwrap();
        <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::write_encryption_key_pair(
            provider.storage(),
            key_package.leaf_node().encryption_key(),
            &encryption_keypair,
        )
        .unwrap();

        // write key package
        <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::write_key_package(
            provider.storage(),
            &key_package_ref,
            &key_package_bundle.key_package,
        )
        .unwrap();

        // // Serialize the old storage. This should become a kat test file
        // let old_storage = serde_json::to_string(provider.storage()).unwrap();

        //  ---- migration starts here ----
        let new_storage_provider = MemoryKeyStore::default();

        // first, read the old data
        let read_key_package: crate::prelude::KeyPackage = <MemoryKeyStore as StorageProvider<
            CURRENT_VERSION,
        >>::key_package(
            provider.storage(), &key_package_ref
        )
        .unwrap()
        .unwrap();
        let read_init_secret: StorageHpkePrivateKey =
            <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::init_private_key(
                provider.storage(),
                &StorageInitKey(read_key_package.hpke_init_key().as_slice()),
            )
            .unwrap()
            .unwrap();
        let read_encryption_keypair: EncryptionKeyPair =
            <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::encryption_key_pair(
                provider.storage(),
                read_key_package.leaf_node().encryption_key(),
            )
            .unwrap()
            .unwrap();

        // then, build the new data from the old data
        let new_version_init_key = NewStorageHpkePrivateKey {
            ciphersuite: read_key_package.ciphersuite(),
            key: read_init_secret.0,
        };

        // insert the new data (encryption key and key package can just be copied)
        <MemoryKeyStore as StorageProvider<V_TEST>>::write_encryption_key_pair(
            &new_storage_provider,
            read_key_package.leaf_node().encryption_key(),
            &read_encryption_keypair,
        )
        .unwrap();
        <MemoryKeyStore as StorageProvider<V_TEST>>::write_init_private_key(
            &new_storage_provider,
            read_key_package.hpke_init_key(),
            &new_version_init_key,
        )
        .unwrap();
        <MemoryKeyStore as StorageProvider<V_TEST>>::write_key_package(
            &new_storage_provider,
            &key_package_ref,
            &read_key_package,
        )
        .unwrap();

        // read the new value from storage
        let read_new_key_package: crate::prelude::KeyPackage =
            <MemoryKeyStore as StorageProvider<V_TEST>>::key_package(
                &new_storage_provider,
                &key_package_ref,
            )
            .unwrap()
            .unwrap();
        let read_new_init_secret: NewStorageHpkePrivateKey =
            <MemoryKeyStore as StorageProvider<V_TEST>>::init_private_key(
                &new_storage_provider,
                read_key_package.hpke_init_key(),
            )
            .unwrap()
            .unwrap();
        let read_new_encryption_keypair: EncryptionKeyPair =
            <MemoryKeyStore as StorageProvider<V_TEST>>::encryption_key_pair(
                &new_storage_provider,
                read_key_package.leaf_node().encryption_key(),
            )
            .unwrap()
            .unwrap();

        // compare it to the old_storage

        assert_eq!(read_new_key_package, key_package);
        assert_eq!(read_new_encryption_keypair, encryption_keypair);
        assert_eq!(read_new_init_secret.key, init_sk.0);
    }
}
