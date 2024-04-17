//! OpenMLS Storage
//!
//! TODO

use openmls_traits::storage;
use openmls_traits::storage::*;
use openmls_traits::types::HpkePrivateKey;
use serde::Deserialize;
use serde::Serialize;

use crate::ciphersuite::hash_ref::ProposalRef;
use crate::group::GroupContext;
use crate::group::GroupId;
use crate::group::InterimTranscriptHash;
use crate::group::QueuedProposal;
use crate::messages::ConfirmationTag;
use crate::treesync::TreeSync;

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

impl Entity<CURRENT_VERSION> for GroupContext {}
impl GroupContextEntity<CURRENT_VERSION> for GroupContext {}

impl Entity<CURRENT_VERSION> for InterimTranscriptHash {}
impl InterimTranscriptHashEntity<CURRENT_VERSION> for InterimTranscriptHash {}

impl Entity<CURRENT_VERSION> for ConfirmationTag {}
impl ConfirmationTagEntity<CURRENT_VERSION> for ConfirmationTag {}

// Crypto
#[derive(Serialize)]
struct StorageInitKey(Vec<u8>);
#[derive(Serialize, Deserialize)]
struct StorageHpkePrivateKey(HpkePrivateKey);

impl Key<CURRENT_VERSION> for StorageInitKey {}
impl InitKey<CURRENT_VERSION> for StorageInitKey {}

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
    use super::*;

    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::{
        crypto::OpenMlsCrypto, storage::StorageProvider, types::Ciphersuite, OpenMlsProvider,
    };

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
        key: Vec<u8>,
    }
    impl storage::HpkePrivateKey<V_TEST> for NewStorageHpkePrivateKey {}
    impl Entity<V_TEST> for NewStorageHpkePrivateKey {}

    #[test]
    fn init_key_upgrade() {
        // Store an old version
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

        // Serialize the old storage. This should be come a kat test file
        let old_storage = serde_json::to_string(provider.storage()).unwrap();

        // Trying to read the new value from the old storage fails at compile time.
        // TODO: test this with something like trybuild
        // let private_key: NewStorageHpkePrivateKey = provider
        //     .storage()
        //     .init_private_key(StorageInitKey(key_pair.public))
        //     .unwrap();
    }
}
