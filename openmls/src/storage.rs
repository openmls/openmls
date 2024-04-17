//! OpenMLS Storage
//!
//! TODO

use openmls_traits::storage::{
    self, ConfirmationTagEntity, Entity, GroupContextEntity, GroupIdKey,
    InterimTranscriptHashEntity, Key, ProposalRefEntity, ProposalRefKey, QueuedProposalEntity,
    TreeSyncEntity, CURRENT_VERSION,
};
use openmls_traits::types::HpkePrivateKey;
use serde::Deserialize;
use serde::Serialize;

use crate::prelude_test::hash_ref::HashReference;
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
impl QueuedProposalEntity<CURRENT_VERSION> for QueuedProposal {}

impl Entity<CURRENT_VERSION> for TreeSync {}
impl TreeSyncEntity<CURRENT_VERSION> for TreeSync {}

impl Key<CURRENT_VERSION> for GroupId {}
impl GroupIdKey<CURRENT_VERSION> for GroupId {}

impl Key<CURRENT_VERSION> for ProposalRef {}
impl Entity<CURRENT_VERSION> for ProposalRef {}
impl ProposalRefKey<CURRENT_VERSION> for ProposalRef {}
impl ProposalRefEntity<CURRENT_VERSION> for ProposalRef {}
impl storage::HashReference<CURRENT_VERSION> for ProposalRef {}

impl Entity<CURRENT_VERSION> for GroupContext {}
impl GroupContextEntity<CURRENT_VERSION> for GroupContext {}

impl Entity<CURRENT_VERSION> for InterimTranscriptHash {}
impl InterimTranscriptHashEntity<CURRENT_VERSION> for InterimTranscriptHash {}

impl Entity<CURRENT_VERSION> for ConfirmationTag {}
impl ConfirmationTagEntity<CURRENT_VERSION> for ConfirmationTag {}

impl Entity<CURRENT_VERSION> for KeyPackage {}
impl storage::KeyPackage<CURRENT_VERSION> for KeyPackage {}

impl Key<CURRENT_VERSION> for EncryptionKey {}
impl storage::HpkePublicKey<CURRENT_VERSION> for EncryptionKey {}

impl Entity<CURRENT_VERSION> for EncryptionKeyPair {}
impl storage::HpkeKeyPair<CURRENT_VERSION> for EncryptionKeyPair {}

// Crypto
#[derive(Serialize)]
struct StorageInitKey(Vec<u8>);
#[derive(Serialize, Deserialize)]
struct StorageHpkePrivateKey(HpkePrivateKey);

impl Key<CURRENT_VERSION> for StorageInitKey {}
impl storage::InitKey<CURRENT_VERSION> for StorageInitKey {}

impl storage::HpkePrivateKey<CURRENT_VERSION> for StorageHpkePrivateKey {}
impl Entity<CURRENT_VERSION> for StorageHpkePrivateKey {}

/// A convenience trait for the current version of the storage.
pub trait StorageProvider: openmls_traits::storage::StorageProvider<CURRENT_VERSION> {}

impl<P: openmls_traits::storage::StorageProvider<CURRENT_VERSION>> StorageProvider for P {}

/// A convenience trait for the OpenMLS provider that defines the storage provider
/// for the current version of storage.
pub trait RefinedProvider:
    openmls_traits::OpenMlsProvider<StorageProvider = Self::Storage>
{
    /// The storage to use
    type Storage: StorageProvider;
}

impl<SP: StorageProvider, OP: openmls_traits::OpenMlsProvider<StorageProvider = SP>> RefinedProvider
    for OP
{
    type Storage = SP;
}

#[cfg(test)]
mod test {
    use crate::{
        group::test_core_group::setup_client,
        prelude::{InitKey, KeyPackageBuilder},
        prelude_test::hash_ref::KeyPackageRef,
    };

    use super::*;

    use openmls_memory_keystore::MemoryKeyStore;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{
        crypto::OpenMlsCrypto,
        storage::{StorageProvider, V_TEST},
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
                StorageInitKey(key_pair.public.clone()),
                StorageHpkePrivateKey(key_pair.private.clone()),
            )
            .unwrap();

        let private_key: StorageHpkePrivateKey = provider
            .storage()
            .init_private_key(StorageInitKey(key_pair.public))
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

    impl storage::HpkePrivateKey<V_TEST> for NewStorageHpkePrivateKey {}
    impl Entity<V_TEST> for NewStorageHpkePrivateKey {}

    impl Entity<V_TEST> for KeyPackage {}
    impl storage::KeyPackage<V_TEST> for KeyPackage {}

    impl Key<V_TEST> for EncryptionKey {}
    impl storage::HpkePublicKey<V_TEST> for EncryptionKey {}

    impl Entity<V_TEST> for EncryptionKeyPair {}
    impl storage::HpkeKeyPair<V_TEST> for EncryptionKeyPair {}

    impl Key<V_TEST> for InitKey {}
    impl storage::InitKey<V_TEST> for InitKey {}

    impl Key<V_TEST> for ProposalRef {}
    impl storage::HashReference<V_TEST> for ProposalRef {}

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
            StorageInitKey(key_package.hpke_init_key().as_slice().to_vec()),
            init_sk,
        );
        <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::write_encryption_key_pair(
            provider.storage(),
            key_package.leaf_node().encryption_key().clone(),
            encryption_keypair,
        );

        // write key package
        <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::write_key_package(
            provider.storage(),
            key_package_ref.clone(),
            key_package_bundle.key_package,
        )
        .unwrap();

        // // Serialize the old storage. This should become a kat test file
        // let old_storage = serde_json::to_string(provider.storage()).unwrap();

        // migration starts here
        let new_storage_provider = MemoryKeyStore::default();

        let read_key_package: crate::prelude::KeyPackage =
            <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::key_package(
                provider.storage(),
                key_package_ref.clone(),
            )
            .unwrap();
        let read_init_secret: StorageHpkePrivateKey =
            <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::init_private_key(
                provider.storage(),
                StorageInitKey(read_key_package.hpke_init_key().as_slice().to_vec()),
            )
            .unwrap();
        let read_encryption_keypair: EncryptionKeyPair =
            <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::encryption_key_pair(
                provider.storage(),
                read_key_package.leaf_node().encryption_key().clone(),
            )
            .unwrap();

        let new_version_init_key = NewStorageHpkePrivateKey {
            ciphersuite: read_key_package.ciphersuite(),
            key: read_init_secret.0,
        };

        <MemoryKeyStore as StorageProvider<V_TEST>>::write_encryption_key_pair(
            &new_storage_provider,
            read_key_package.leaf_node().encryption_key().clone(),
            read_encryption_keypair,
        )
        .unwrap();
        <MemoryKeyStore as StorageProvider<V_TEST>>::write_init_private_key(
            &new_storage_provider,
            read_key_package.hpke_init_key().clone(),
            new_version_init_key,
        )
        .unwrap();
        <MemoryKeyStore as StorageProvider<V_TEST>>::write_key_package(
            &new_storage_provider,
            key_package_ref,
            read_key_package,
        )
        .unwrap();

        // Trying to read the new value from the old storage fails at compile time.
        // TODO: test this with something like trybuild
        // let private_key: NewStorageHpkePrivateKey = provider
        //     .storage()
        //     .init_private_key(StorageInitKey(key_pair.public))
        //     .unwrap();
    }
}
