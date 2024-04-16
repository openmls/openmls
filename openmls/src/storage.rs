#[derive(Debug, Clone, Default)]
pub struct OpenMlsTypes;

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

impl Entity<1> for QueuedProposal {}
impl QueuedProposalEntity<1> for QueuedProposal {}

impl Entity<1> for TreeSync {}
impl TreeSyncEntity<1> for TreeSync {}

impl Key<1> for GroupId {}
impl GroupIdKey<1> for GroupId {}

impl Key<1> for ProposalRef {}
impl Entity<1> for ProposalRef {}
impl ProposalRefKey<1> for ProposalRef {}
impl ProposalRefEntity<1> for ProposalRef {}

impl Entity<1> for GroupContext {}
impl GroupContextEntity<1> for GroupContext {}

impl Entity<1> for InterimTranscriptHash {}
impl InterimTranscriptHashEntity<1> for InterimTranscriptHash {}

impl Entity<1> for ConfirmationTag {}
impl ConfirmationTagEntity<1> for ConfirmationTag {}

// Crypto
#[derive(Serialize)]
struct StorageInitKey(Vec<u8>);
#[derive(Serialize, Deserialize)]
struct StorageHpkePrivateKey(HpkePrivateKey);

impl Key<1> for StorageInitKey {}
impl InitKey<1> for StorageInitKey {}

impl storage::HpkePrivateKey<1> for StorageHpkePrivateKey {}
impl Entity<1> for StorageHpkePrivateKey {}

pub trait StorageProvider: openmls_traits::storage::StorageProvider<1> {}

impl<P: openmls_traits::storage::StorageProvider<1>> StorageProvider for P {}

pub trait RefinedProvider:
    openmls_traits::OpenMlsProvider<StorageProvider = Self::Storage>
{
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
            .write_hpke_private_key(
                StorageInitKey(key_pair.public.clone()),
                StorageHpkePrivateKey(key_pair.private.clone()),
            )
            .unwrap();

        let private_key: StorageHpkePrivateKey = provider
            .storage()
            .hpke_private_key(StorageInitKey(key_pair.public))
            .unwrap();
        assert_eq!(private_key.0, key_pair.private);
    }
}
