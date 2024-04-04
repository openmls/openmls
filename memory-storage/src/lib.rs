use impl_storagekey::QueuedProposals;
use openmls_spec_types::hpke::*;
use openmls_spec_types::key_package::{KeyPackage, KeyPackageRef};
use openmls_spec_types::keys::{EncryptionKey, InitKey};
use openmls_spec_types::proposals::ProposalRef;
use openmls_spec_types::GroupId;
use openmls_traits::storage::{
    CreateError, DeleteError, EpochKeyPairId, GetError, InsertError, Key, OpenError, PskBundle,
    PskBundleId, Storage, Stored as StoredTrait, StoredProposal, Update, UpdateError,
};

const MAX_SUPPORTED_VERSION: u16 = 1;
const MIN_SUPPORTED_VERSION: u16 = 1;

pub struct Stored<T>(T);

impl<T> openmls_traits::storage::Stored<T> for Stored<T> {
    fn get(self) -> T {
        self.0
    }
}

/// The kv module describes the underlying byte-oriented Key Value Store
pub mod kv;

trait StorageKey {
    fn key_bytes(&self) -> Vec<u8>;
    fn into_key(self) -> Key;
}

mod impl_storagekey;

#[derive(Default, Debug, Clone)]
pub struct KvStoreStorage<KvStore: kv::KeyValueStore>(KvStore);

impl<KvStore: kv::KeyValueStore> KvStoreStorage<KvStore> {
    pub fn open(kv: KvStore) -> Result<Self, OpenError<KvStore::InternalError>> {
        match kv.get(b"version") {
            Ok(version_byte_vec) => {
                let version_bytes: [u8; 2] = version_byte_vec
                    .try_into()
                    .map_err(|_| OpenError::InvalidFormat)?;
                let version = u16::from_be_bytes(version_bytes);
                if version > MAX_SUPPORTED_VERSION {
                    Err(OpenError::UnsupportedVersion(version))
                } else {
                    Ok(Self(kv))
                }
            }
            Err(kv::GetError::InternalError(e)) => Err(OpenError::InternalError(e)),
            Err(kv::GetError::NotFound(_)) => Err(OpenError::InvalidFormat),
        }
    }

    pub fn create(mut kv: KvStore) -> Result<Self, CreateError<KvStore::InternalError>> {
        match kv.insert(
            b"version".to_vec(),
            MAX_SUPPORTED_VERSION.to_be_bytes().to_vec(),
        ) {
            Ok(_) => Ok(Self(kv)),
            Err(e) => match e {
                kv::InsertError::InternalError(e) => Err(CreateError::InternalError(e)),
                kv::InsertError::AlreadyExists(_) => Err(CreateError::AlreadyCreated),
            },
        }
    }
}

impl<KvStore: kv::KeyValueStore<SerializeError = serde_json::Error>> Storage<KvStore>
    for KvStoreStorage<KvStore>
{
    type Stored<T> = Stored<T>;

    fn current_version(&self) -> u16 {
        let version_bytes: [u8; 2] = self.0.get(b"version").unwrap().try_into().unwrap();
        u16::from_be_bytes(version_bytes)
    }

    fn apply_update(
        &mut self,
        update: openmls_traits::storage::Update,
    ) -> Result<(), UpdateError<KvStore::InternalError, KvStore::SerializeError>> {
        match update {
            Update::InsertEpochKeyPairs(id, key_pairs) => {
                self.insert_epoch_key_pairs(&id, key_pairs)?
            }
            Update::DeleteEpochKeyPairs(id) => self.delete_epoch_key_pairs(&id)?,
            Update::InsertEncryptionSecretKey(public_key, secret_key) => {
                self.insert_encryption_secret_key(&public_key, secret_key)?
            }
            Update::DeleteEncryptionSecretKey(public_key) => {
                self.delete_encryption_secret_key(&public_key)?
            }
            Update::InsertInitSecretKey(public_key, secret_key) => {
                self.insert_init_secret_key(&public_key, secret_key)?
            }
            Update::DeleteInitSecretKey(public_key) => self.delete_init_secret_key(&public_key)?,
            Update::InsertKeyPackage(key_pkg_ref, key_pkg) => {
                self.insert_key_package(&key_pkg_ref, key_pkg)?
            }
            Update::InsertKeyPackageWithEncryptionKey(key_pkg_ref, key_pkg, secret_key) => {
                self.insert_key_package_with_encryption_key(&key_pkg_ref, key_pkg, secret_key)?
            }
            Update::InsertKeyPackageWithInitKey(key_pkg_ref, key_pkg, secret_key) => {
                self.insert_key_package_with_init_key(&key_pkg_ref, key_pkg, secret_key)?
            }
            Update::InsertKeyPackageWithKeys {
                key_pkg_ref,
                key_pkg,
                encryption_key,
                init_key,
            } => {
                self.insert_key_package_with_keys(&key_pkg_ref, key_pkg, encryption_key, init_key)?
            }
            Update::DeleteKeyPackage(key_pkg_ref) => self.delete_key_package(&key_pkg_ref)?,
            Update::InsertPskBundle(psk_bundle_id, psk_bundle) => {
                self.insert_psk_bundle(&psk_bundle_id, psk_bundle)?
            }
            Update::DeletePskBundle(id) => self.delete_psk_bundle(&id)?,
            Update::QueueProposal(stored_proposal) => self.queue_proposal(stored_proposal)?,
            Update::DeleteProposal(proposal_ref) => self.delete_queued_proposal(proposal_ref)?,

            Update::ClearProposalQueue => self.clear_proposal_queue()?,
        };

        Ok(())
    }

    fn get_epoch_key_pairs(
        &self,
        epoch_key_pair_id: &EpochKeyPairId,
    ) -> Result<Vec<Stored<HpkeKeyPair>>, GetError<KvStore::InternalError, KvStore::SerializeError>>
    {
        let key = epoch_key_pair_id.key();
        let value_bytes = self.0.get(&key).map_err(kv::GetError::into_storage_error(
            epoch_key_pair_id.clone().into_key(),
        ))?;
        serde_json::from_slice(&value_bytes)
            .map_err(GetError::DeserializeFailed)
            .map(|list: Vec<_>| list.into_iter().map(Stored).collect())
    }

    fn get_encryption_secret_key(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Stored<HpkePrivateKey>, GetError<KvStore::InternalError, KvStore::SerializeError>>
    {
        let key = public_key.key_bytes();
        let value_bytes = self.0.get(&key).map_err(kv::GetError::into_storage_error(
            public_key.clone().into_key(),
        ))?;
        serde_json::from_slice(&value_bytes)
            .map_err(GetError::DeserializeFailed)
            .map(Stored)
    }

    fn get_init_secret_key(
        &self,
        public_key: &InitKey,
    ) -> Result<Stored<HpkePrivateKey>, GetError<KvStore::InternalError, KvStore::SerializeError>>
    {
        let key = public_key.key_bytes();
        let value_bytes = self.0.get(&key).map_err(kv::GetError::into_storage_error(
            public_key.clone().into_key(),
        ))?;
        serde_json::from_slice(&value_bytes)
            .map_err(GetError::DeserializeFailed)
            .map(Stored)
    }

    fn get_key_package(
        &self,
        key_pkg_ref: &KeyPackageRef,
    ) -> Result<Stored<KeyPackage>, GetError<KvStore::InternalError, KvStore::SerializeError>> {
        let key = key_pkg_ref.key_bytes();
        let value_bytes = self.0.get(&key).map_err(kv::GetError::into_storage_error(
            key_pkg_ref.clone().into_key(),
        ))?;
        serde_json::from_slice(&value_bytes)
            .map_err(GetError::DeserializeFailed)
            .map(Stored)
    }

    fn get_psk_bundle(
        &self,
        id: &PskBundleId,
    ) -> Result<Stored<PskBundle>, GetError<KvStore::InternalError, KvStore::SerializeError>> {
        self.0
            .get(&id.key_bytes())
            .map_err(kv::GetError::into_storage_error(id.clone().into_key()))
            .map(PskBundle)
            .map(Stored)
    }

    fn get_mls_group(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, GetError<KvStore::InternalError, KvStore::SerializeError>> {
        self.0
            .get(&group_id.key_bytes())
            .map_err(kv::GetError::into_storage_error(
                group_id.clone().into_key(),
            ))
    }

    fn get_queued_proposals(
        &self,
    ) -> Result<
        Vec<Stored<StoredProposal>>,
        GetError<
            <KvStore as openmls_traits::storage::Platform>::InternalError,
            <KvStore as openmls_traits::storage::Platform>::SerializeError,
        >,
    > {
        // first fetch and deserialize the refs in the queue
        let queue_key = QueuedProposals;
        let queue_bytes = match self.0.get(&queue_key.key_bytes()) {
            Ok(queue_bytes) => queue_bytes,
            Err(kv::GetError::NotFound(_)) => return Ok(vec![]),
            Err(kv::GetError::InternalError(e)) => return Err(GetError::InternalError(e)),
        };

        let queue: Vec<ProposalRef> =
            serde_json::from_slice(&queue_bytes).map_err(GetError::DeserializeFailed)?;
        queue
            .into_iter()
            .map(|proposal_ref| {
                // then, for each ref, get and deserialize the proposal
                let proposal_key = proposal_ref.key_bytes();
                let proposal_bytes =
                    self.0
                        .get(&proposal_key)
                        .map_err(kv::GetError::into_storage_error(
                            proposal_ref.clone().into_key(),
                        ))?;
                let stored_proposal: Stored<StoredProposal> =
                    serde_json::from_slice(&proposal_bytes)
                        .map_err(GetError::DeserializeFailed)
                        .map(Stored)?;

                Ok(stored_proposal)
            })
            .collect()
    }
}

impl<KvStore: kv::KeyValueStore<SerializeError = serde_json::Error>> KvStoreStorage<KvStore> {
    fn insert_epoch_key_pairs(
        &mut self,
        epoch_key_pair_id: &EpochKeyPairId,
        key_pairs: Vec<HpkeKeyPair>,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        let key = epoch_key_pair_id.key();
        let value_bytes = serde_json::to_vec(&key_pairs).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(key, value_bytes)
            .map_err(kv::InsertError::into_storage_error(
                epoch_key_pair_id.clone().into_key(),
            ))
    }

    fn delete_epoch_key_pairs(
        &mut self,
        epoch_key_pair_id: &EpochKeyPairId,
    ) -> Result<(), DeleteError<KvStore::InternalError, KvStore::SerializeError>> {
        let key = epoch_key_pair_id.key();
        self.0
            .delete(&key)
            .map_err(kv::DeleteError::into_storage_error(
                epoch_key_pair_id.clone().into_key(),
            ))
    }

    fn insert_encryption_secret_key(
        &mut self,
        public_key: &EncryptionKey,
        secret_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        let key = public_key.key_bytes();
        let value_bytes = serde_json::to_vec(&secret_key).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(key, value_bytes)
            .map_err(kv::InsertError::into_storage_error(
                public_key.clone().into_key(),
            ))
    }

    fn delete_encryption_secret_key(
        &mut self,
        public_key: &EncryptionKey,
    ) -> Result<(), DeleteError<KvStore::InternalError, KvStore::SerializeError>> {
        let key = public_key.key_bytes();
        self.0
            .delete(&key)
            .map_err(kv::DeleteError::into_storage_error(
                public_key.clone().into_key(),
            ))
    }

    fn insert_init_secret_key(
        &mut self,
        public_key: &InitKey,
        secret_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        let key = public_key.key_bytes();
        let value_bytes = serde_json::to_vec(&secret_key).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(key, value_bytes)
            .map_err(kv::InsertError::into_storage_error(
                public_key.clone().into_key(),
            ))
    }

    fn delete_init_secret_key(
        &mut self,
        public_key: &InitKey,
    ) -> Result<(), DeleteError<KvStore::InternalError, KvStore::SerializeError>> {
        let key = public_key.key_bytes();
        self.0
            .delete(&key)
            .map_err(kv::DeleteError::into_storage_error(
                public_key.clone().into_key(),
            ))
    }

    fn delete_key_package(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
    ) -> Result<(), DeleteError<KvStore::InternalError, KvStore::SerializeError>> {
        // fetch the key package before deleting, so we can also delete the secrets
        let key_pkg = self
            .get_key_package(key_pkg_ref)
            .map_err(DeleteError::GetKeyPackageError)?
            .get();

        self.0
            .delete(&key_pkg_ref.key_bytes())
            .map_err(kv::DeleteError::into_storage_error(
                key_pkg_ref.clone().into_key(),
            ))?;

        // also delete the secret keys, if they are known
        match self.delete_init_secret_key(&key_pkg.payload.init_key) {
            Err(DeleteError::NotFound(_)) => Ok(()),
            other => other,
        }?;

        match self.delete_encryption_secret_key(&key_pkg.payload.leaf_node.payload.encryption_key) {
            Err(DeleteError::NotFound(_)) => Ok(()),
            other => other,
        }
    }

    fn insert_key_package(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        let bytes = serde_json::to_vec(&key_pkg).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(key_pkg_ref.key_bytes(), bytes)
            .map_err(kv::InsertError::into_storage_error(
                key_pkg_ref.clone().into_key(),
            ))
    }

    fn insert_key_package_with_keys(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        encryption_key: HpkePrivateKey,
        init_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        self.insert_init_secret_key(&key_pkg.payload.init_key, init_key)?;
        self.insert_encryption_secret_key(
            &key_pkg.payload.leaf_node.payload.encryption_key,
            encryption_key,
        )?;
        self.insert_key_package(key_pkg_ref, key_pkg)
    }

    fn insert_key_package_with_encryption_key(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        encryption_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        self.insert_encryption_secret_key(
            &key_pkg.payload.leaf_node.payload.encryption_key,
            encryption_key,
        )?;
        self.insert_key_package(key_pkg_ref, key_pkg)
    }

    fn insert_key_package_with_init_key(
        &mut self,
        key_pkg_ref: &KeyPackageRef,
        key_pkg: KeyPackage,
        init_key: HpkePrivateKey,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        self.insert_init_secret_key(&key_pkg.payload.init_key, init_key)?;
        self.insert_key_package(key_pkg_ref, key_pkg)
    }

    fn insert_psk_bundle(
        &mut self,
        id: &PskBundleId,
        bundle: PskBundle,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        self.0
            .insert(id.key_bytes(), bundle.0)
            .map_err(kv::InsertError::into_storage_error(id.clone().into_key()))
    }

    fn delete_psk_bundle(
        &mut self,
        id: &PskBundleId,
    ) -> Result<(), DeleteError<KvStore::InternalError, KvStore::SerializeError>> {
        self.0
            .delete(&id.key_bytes())
            .map_err(kv::DeleteError::into_storage_error(id.clone().into_key()))
    }

    fn insert_mls_group(
        &mut self,
        group_id: &GroupId,
        group: Vec<u8>,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        self.0
            .insert(group_id.key_bytes(), group)
            .map_err(kv::InsertError::into_storage_error(
                group_id.clone().into_key(),
            ))
    }

    fn delete_mls_group(
        &mut self,
        group_id: &GroupId,
    ) -> Result<(), DeleteError<KvStore::InternalError, KvStore::SerializeError>> {
        self.0
            .delete(&group_id.key_bytes())
            .map_err(kv::DeleteError::into_storage_error(
                group_id.clone().into_key(),
            ))
    }

    fn queue_proposal(
        &mut self,
        stored_proposal: StoredProposal,
    ) -> Result<(), InsertError<KvStore::InternalError, KvStore::SerializeError>> {
        let proposal_key = stored_proposal.proposal_ref.key_bytes();
        let value = serde_json::to_vec(&stored_proposal).map_err(InsertError::SerializeFailed)?;
        self.0
            .insert(proposal_key.clone(), value)
            .map_err(kv::InsertError::into_storage_error(
                stored_proposal.proposal_ref.clone().into_key(),
            ))?;

        // we need to track the elements in the queue in a separate entry
        let queue_key = QueuedProposals.key_bytes();
        match self.0.get(&queue_key) {
            // there already is data. append the new key and write back
            Ok(queue_bytes) => {
                let mut proposals: Vec<ProposalRef> =
                    serde_json::from_slice(&queue_bytes).map_err(InsertError::SerializeFailed)?;
                proposals.push(stored_proposal.proposal_ref);
                let new_queue_bytes =
                    serde_json::to_vec(&proposals).map_err(InsertError::SerializeFailed)?;
                self.0.insert(queue_key, new_queue_bytes).map_err(
                    kv::InsertError::into_storage_error(QueuedProposals.into_key()),
                )
            }
            // there is no data yet. just write this key
            Err(kv::GetError::NotFound(_)) => {
                let proposals = vec![stored_proposal.proposal_ref];
                let new_queue_bytes =
                    serde_json::to_vec(&proposals).map_err(InsertError::SerializeFailed)?;
                self.0.insert(queue_key, new_queue_bytes).map_err(
                    kv::InsertError::into_storage_error(QueuedProposals.into_key()),
                )
            }
            // an internal error occurred
            Err(kv::GetError::InternalError(e)) => Err(InsertError::InternalError(e)),
        }
    }

    fn clear_proposal_queue(
        &mut self,
    ) -> Result<(), DeleteError<KvStore::InternalError, KvStore::SerializeError>> {
        // first, fetch and deserialize the refs in the queue
        let queue_key = QueuedProposals.key_bytes();
        match self.0.get(&queue_key) {
            // there is something in the queue. parse it and delete all the entries
            Ok(queue_bytes) => {
                let proposal_refs: Vec<ProposalRef> = serde_json::from_slice(&queue_bytes)
                    .map_err(GetError::DeserializeFailed)
                    .map_err(DeleteError::GetProposalQueueError)?;

                for proposal_ref in proposal_refs {
                    self.delete_queued_proposal(proposal_ref)?;
                }

                self.0
                    .delete(&queue_key)
                    .map_err(kv::DeleteError::into_storage_error(
                        QueuedProposals.into_key(),
                    ))
            }
            // the queue is already empty
            Err(kv::GetError::NotFound(_)) => Ok(()),
            // an internal error occurred
            Err(kv::GetError::InternalError(e)) => Err(DeleteError::InternalError(e)),
        }
    }

    fn delete_queued_proposal(
        &mut self,
        proposal_ref: ProposalRef,
    ) -> Result<(), DeleteError<KvStore::InternalError, KvStore::SerializeError>> {
        let key = proposal_ref.key_bytes();
        self.0
            .delete(&key)
            .map_err(kv::DeleteError::into_storage_error(proposal_ref.into_key()))
    }
}

/// Example.
/// MigrationV1V2Error explains why a migration from version 1 to version 2 failed.
#[derive(Clone, Debug)]
pub enum MigrationV1V2Error<InnerError> {
    InternalError(InnerError),
}

// an example for how we could implement migrations
impl<KvStore: kv::KeyValueStore> KvStoreStorage<KvStore> {
    fn migrate_v1_v2(kv: KvStore) -> Result<(), MigrationV1V2Error<KvStore::InternalError>> {}
}
