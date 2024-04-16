mod kv_store;
pub mod mem_kv_store;

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

use mem_kv_store::{KvGetError, KvInsertError};
use openmls_traits::storage::{self, GetErrorKind, UpdateErrorKind};

const V1: usize = 1;

#[derive(Debug)]
pub struct KvStoreStorage<KvStore: kv_store::KvStore, Ts: storage::Types<V1>>(RwLock<KvStore>, Ts);

impl<KvStore: kv_store::KvStore + Default, Ts: storage::Types<V1>> Default
    for KvStoreStorage<KvStore, Ts>
{
    fn default() -> Self {
        Self::create(Default::default()).unwrap()
    }
}

#[derive(Debug)]
pub enum OpenError {
    InternalError,
    Unformatted,
    InvalidFormat,
    VersionMismatch(usize),
}

#[derive(Debug)]
pub enum CreateError {
    InternalError,
    AlreadyCreated,
}

impl<KvStore: kv_store::KvStore, Ts: storage::Types<V1>> KvStoreStorage<KvStore, Ts> {
    pub fn open(store: KvStore) -> Result<Self, OpenError> {
        let key = Key::<Ts>::Version
            .key()
            .map_err(|_| OpenError::InternalError)?;
        let version_bytes = store.get(&key).map_err(|err| match err {
            KvGetError::NotFound(_) => OpenError::Unformatted,
            KvGetError::Internal(_) => OpenError::InternalError,
        })?;

        let version: usize =
            serde_json::from_slice(&version_bytes).map_err(|_| OpenError::InvalidFormat)?;

        if version != 1 {
            Err(OpenError::VersionMismatch(version))
        } else {
            Ok(Self(RwLock::new(store), Ts::default()))
        }
    }

    pub fn create(store: KvStore) -> Result<Self, CreateError> {
        let key = Key::<Ts>::Version
            .key()
            .map_err(|_| CreateError::InternalError)?;

        if store.get(&key).is_err() {
            Ok(Self(RwLock::new(store), Ts::default()))
        } else {
            Err(CreateError::AlreadyCreated)
        }
    }
}

use thiserror::Error;

#[derive(Debug, Error)]
pub enum GetError<InternalError> {
    #[error("key {0:?} not found")]
    NotFound(Vec<u8>),
    #[error("error encoding key {0:?}")]
    KeyEncodeError(serde_json::Error),
    #[error("error decoding value")]
    ValueDecodeError(serde_json::Error),
    #[error(transparent)]
    KvGetError(#[from] KvGetError<InternalError>),
    #[error("lock poisoned")]
    LockPoisonedError,
}

impl<InternalError: core::fmt::Debug + PartialEq + std::error::Error>
    openmls_traits::storage::GetError for GetError<InternalError>
{
    fn error_kind(&self) -> GetErrorKind {
        match self {
            GetError::NotFound(_) => GetErrorKind::NotFound,
            GetError::KeyEncodeError(_) | GetError::ValueDecodeError(_) => GetErrorKind::Encoding,
            GetError::KvGetError(_) | GetError::LockPoisonedError => GetErrorKind::Internal,
        }
    }
}

// This impl block implements partial equality by comparing the error strings,
// as recommended here:
// https://github.com/serde-rs/json/issues/271
impl<InternalError: PartialEq> PartialEq for GetError<InternalError> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::NotFound(l0), Self::NotFound(r0)) => l0 == r0,
            (Self::KeyEncodeError(l0), Self::KeyEncodeError(r0))
            | (Self::ValueDecodeError(l0), Self::ValueDecodeError(r0)) => {
                l0.to_string() == r0.to_string()
            }
            (Self::KvGetError(l0), Self::KvGetError(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

impl<InternalError: core::fmt::Debug + PartialEq + std::error::Error>
    openmls_traits::storage::UpdateError for UpdateError<InternalError>
{
    fn error_kind(&self) -> storage::UpdateErrorKind {
        match self {
            UpdateError::KeyEncodeError(_)
            | UpdateError::ValueEncodeError(_)
            | UpdateError::ValueDecodeError(_) => UpdateErrorKind::Encoding,
            UpdateError::KvInsertError(err) => match err {
                KvInsertError::AlreadyExists(_, _) => UpdateErrorKind::AlreadyExists,
                KvInsertError::Internal(_) => UpdateErrorKind::Internal,
            },
            UpdateError::KvGetError(err) => UpdateErrorKind::Internal,
            UpdateError::GetError(_) => UpdateErrorKind::Internal,
            UpdateError::LockPoisonedError => UpdateErrorKind::LockPoisoned,
        }
    }
}

#[derive(Debug, Error)]
pub enum UpdateError<InternalError> {
    #[error("error encoding key {0:?}")]
    KeyEncodeError(serde_json::Error),
    #[error("error encoding value")]
    ValueEncodeError(serde_json::Error),
    #[error("error decoding value")]
    ValueDecodeError(serde_json::Error),
    #[error(transparent)]
    KvInsertError(KvInsertError<InternalError>),
    #[error(transparent)]
    KvGetError(KvGetError<InternalError>),
    #[error(transparent)]
    GetError(GetError<InternalError>),
    #[error("lock poisoned")]
    LockPoisonedError,
}

// This impl block implements partial equality by comparing the error strings,
// as recommended here:
// https://github.com/serde-rs/json/issues/271
impl<InternalError: PartialEq> PartialEq for UpdateError<InternalError> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::KeyEncodeError(l0), Self::KeyEncodeError(r0))
            | (Self::ValueEncodeError(l0), Self::ValueEncodeError(r0))
            | (Self::ValueDecodeError(l0), Self::ValueDecodeError(r0)) => {
                l0.to_string() == r0.to_string()
            }
            (Self::KvInsertError(l0), Self::KvInsertError(r0)) => l0 == r0,
            (Self::KvGetError(l0), Self::KvGetError(r0)) => l0 == r0,
            (Self::GetError(l0), Self::GetError(r0)) => l0 == r0,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
    }
}

// The variant describes the type of the key, and the contents are what the key is made of
enum Key<'a, Types: storage::Types<V1>> {
    Version,
    QueuedProposal(&'a Types::GroupId, &'a Types::ProposalRef),
    QueuedProposalsRefList(&'a Types::GroupId),
    TreeSync(&'a Types::GroupId),
    GroupContext(&'a Types::GroupId),
    InterimTranscriptHash(&'a Types::GroupId),
    ConfirmationTag(&'a Types::GroupId),
}

impl<'a, Types: storage::Types<V1>> Key<'a, Types> {
    fn domain_prefix(&self) -> [u8; 2] {
        match self {
            Key::Version => [0, 0],
            Key::QueuedProposal(_, _) => [0, 1],
            Key::QueuedProposalsRefList(_) => [0, 2],
            Key::TreeSync(_) => [0, 3],
            Key::GroupContext(_) => [0, 4],
            Key::InterimTranscriptHash(_) => [0, 5],
            Key::ConfirmationTag(_) => [0, 6],
        }
    }

    fn key(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.domain_prefix());

        match self {
            Key::QueuedProposal(group_id, proposal_ref) => {
                // TODO: This is not necessarily injective! Use better encoding
                //          Though tbf it's mostly a problem if both are numbers I think
                serde_json::to_writer(&mut out, group_id)?;
                serde_json::to_writer(&mut out, proposal_ref)?;
            }
            Key::QueuedProposalsRefList(group_id) => {
                serde_json::to_writer(&mut out, group_id)?;
            }
            Key::TreeSync(group_id) => {
                serde_json::to_writer(&mut out, group_id)?;
            }
            Key::GroupContext(group_id) => {
                serde_json::to_writer(&mut out, group_id)?;
            }
            Key::InterimTranscriptHash(group_id) => {
                serde_json::to_writer(&mut out, group_id)?;
            }
            Key::ConfirmationTag(group_id) => {
                serde_json::to_writer(&mut out, group_id)?;
            }
            Key::Version => {}
        }

        Ok(out)
    }
}

impl<'a, Types: storage::Types<1>> From<&'a storage::Update<1, Types>> for Key<'a, Types> {
    fn from(value: &'a storage::Update<1, Types>) -> Self {
        match value {
            storage::Update::QueueProposal(group_id, proposal_ref, _) => {
                Self::QueuedProposal(group_id, proposal_ref)
            }
            storage::Update::WriteTreeSync(group_id, _) => Self::TreeSync(group_id),
            storage::Update::WriteGroupContext(group_id, _) => Self::GroupContext(group_id),
            storage::Update::WriteInterimTranscriptHash(group_id, _) => {
                Self::InterimTranscriptHash(group_id)
            }
            storage::Update::WriteConfirmationTag(group_id, _) => Self::ConfirmationTag(group_id),
            storage::Update::SignatureKeypair(_, _) => todo!(),
        }
    }
}

// TODO: implement Error with source for the error types

impl<KvStore: kv_store::KvStore, Types: storage::Types<V1>> storage::StorageProvider<V1>
    for KvStoreStorage<KvStore, Types>
{
    type Types = Types;
    type GetError = GetError<KvStore::InternalError>;
    type UpdateError = UpdateError<KvStore::InternalError>;

    fn apply_update(&self, update: storage::Update<V1, Types>) -> Result<(), Self::UpdateError> {
        let mut store = self.write_update()?;

        let key = Key::<Types>::from(&update)
            .key()
            .map_err(UpdateError::KeyEncodeError)?;

        match update {
            storage::Update::QueueProposal(group_id, proposal_ref, queued_proposal) => {
                let proposal_key = key;
                let proposal_refs_key = Key::<Types>::QueuedProposalsRefList(&group_id)
                    .key()
                    .map_err(UpdateError::KeyEncodeError)?;

                let proposal_value =
                    serde_json::to_vec(&queued_proposal).map_err(UpdateError::ValueEncodeError)?;

                let mut proposal_refs: Vec<Types::ProposalRef> = match store.get(&proposal_refs_key)
                {
                    Ok(proposal_queue_bytes) => serde_json::from_slice(&proposal_queue_bytes)
                        .map_err(UpdateError::ValueEncodeError),
                    Err(kv_store::KvGetError::NotFound(_)) => Ok(vec![]),
                    Err(e @ kv_store::KvGetError::Internal(_)) => {
                        Result::<Vec<_>, _>::Err(UpdateError::KvGetError(e))
                    }
                }?;

                proposal_refs.push(proposal_ref);

                let proposal_refs_bytes =
                    serde_json::to_vec(&proposal_refs).map_err(UpdateError::ValueEncodeError)?;

                match store.insert(proposal_refs_key, proposal_refs_bytes) {
                    Ok(v) => Ok(v),
                    Err(err) => match err {
                        KvInsertError::AlreadyExists(_, _) => Ok(()),
                        KvInsertError::Internal(_) => Err(UpdateError::KvInsertError(err)),
                    },
                }?;
                match store.insert(proposal_key, proposal_value) {
                    Ok(v) => Ok(v),
                    Err(err) => match err {
                        KvInsertError::AlreadyExists(_, _) => Ok(()),
                        KvInsertError::Internal(_) => Err(UpdateError::KvInsertError(err)),
                    },
                }?;
            }
            storage::Update::WriteTreeSync(_group_id, tree_sync) => {
                let value_bytes =
                    serde_json::to_vec(&tree_sync).map_err(UpdateError::ValueEncodeError)?;

                match store.insert(key, value_bytes) {
                    Ok(v) => Ok(v),
                    Err(err) => match err {
                        KvInsertError::AlreadyExists(_, _) => Ok(()),
                        KvInsertError::Internal(_) => Err(UpdateError::KvInsertError(err)),
                    },
                }?
            }
            storage::Update::WriteGroupContext(_group_id, group_context) => {
                let value_bytes =
                    serde_json::to_vec(&group_context).map_err(UpdateError::ValueEncodeError)?;

                match store.insert(key, value_bytes) {
                    Ok(v) => Ok(v),
                    Err(err) => match err {
                        KvInsertError::AlreadyExists(_, _) => Ok(()),
                        KvInsertError::Internal(_) => Err(UpdateError::KvInsertError(err)),
                    },
                }?
            }
            storage::Update::WriteInterimTranscriptHash(_group_id, interim_transcript_hash) => {
                let value_bytes = serde_json::to_vec(&interim_transcript_hash)
                    .map_err(UpdateError::ValueEncodeError)?;

                match store.insert(key, value_bytes) {
                    Ok(v) => Ok(v),
                    Err(err) => match err {
                        KvInsertError::AlreadyExists(_, _) => Ok(()),
                        KvInsertError::Internal(_) => Err(UpdateError::KvInsertError(err)),
                    },
                }?
            }
            storage::Update::WriteConfirmationTag(_group_id, confirmation_tag) => {
                let value_bytes =
                    serde_json::to_vec(&confirmation_tag).map_err(UpdateError::ValueEncodeError)?;

                match store.insert(key, value_bytes) {
                    Ok(v) => Ok(v),
                    Err(err) => match err {
                        KvInsertError::AlreadyExists(_, _) => Ok(()),
                        KvInsertError::Internal(_) => Err(UpdateError::KvInsertError(err)),
                    },
                }?
            }
            storage::Update::SignatureKeypair(_, _) => todo!(),
        }

        Ok(())
    }

    // TODO: take lock at the start and then iterate
    fn apply_updates(
        &self,
        updates: Vec<storage::Update<V1, Types>>,
    ) -> Result<(), Self::UpdateError> {
        for update in updates {
            self.apply_update(update)?
        }

        Ok(())
    }

    fn get_queued_proposals(
        &self,
        group_id: &Types::GroupId,
    ) -> Result<Vec<Types::QueuedProposal>, Self::GetError> {
        let store = self.read_get()?;

        storage::StorageProvider::get_queued_proposal_refs(self, group_id)?
            .into_iter()
            .map(|proposal_ref| {
                let proposal_key = Key::<Types>::QueuedProposal(group_id, &proposal_ref)
                    .key()
                    .map_err(GetError::KeyEncodeError)?;
                let value_bytes = store.get(&proposal_key).map_err(|e| match e {
                    kv_store::KvGetError::NotFound(key) => GetError::NotFound(key),
                    kv_store::KvGetError::Internal(_) => GetError::KvGetError(e),
                })?;

                serde_json::from_slice(&value_bytes).map_err(GetError::ValueDecodeError)
            })
            .collect()
    }

    fn get_queued_proposal_refs(
        &self,
        group_id: &Types::GroupId,
    ) -> Result<Vec<Types::ProposalRef>, Self::GetError> {
        let store = self.read_get()?;

        let key = Key::<Types>::QueuedProposalsRefList(group_id)
            .key()
            .map_err(GetError::KeyEncodeError)?;

        let value_bytes = store.get(&key).map_err(|e| match e {
            kv_store::KvGetError::NotFound(key) => GetError::NotFound(key),
            kv_store::KvGetError::Internal(_) => GetError::KvGetError(e),
        })?;

        Ok(serde_json::from_slice(&value_bytes).map_err(GetError::ValueDecodeError)?)
    }

    fn get_treesync(
        &self,
        group_id: &<Self::Types as storage::Types<V1>>::GroupId,
    ) -> Result<<Self::Types as storage::Types<V1>>::TreeSync, Self::GetError> {
        let store = self.read_get()?;

        let key = Key::<Types>::QueuedProposalsRefList(group_id)
            .key()
            .map_err(GetError::KeyEncodeError)?;

        let value_bytes = store.get(&key).map_err(|e| match e {
            kv_store::KvGetError::NotFound(key) => GetError::NotFound(key),
            kv_store::KvGetError::Internal(_) => GetError::KvGetError(e),
        })?;

        Ok(serde_json::from_slice(&value_bytes).map_err(GetError::ValueDecodeError)?)
    }

    fn get_group_context(
        &self,
        group_id: &<Self::Types as storage::Types<V1>>::GroupId,
    ) -> Result<<Self::Types as storage::Types<V1>>::GroupContext, Self::GetError> {
        let store = self.read_get()?;

        let key = Key::<Types>::GroupContext(group_id)
            .key()
            .map_err(GetError::KeyEncodeError)?;

        let value_bytes = store.get(&key).map_err(|e| match e {
            kv_store::KvGetError::NotFound(key) => GetError::NotFound(key),
            kv_store::KvGetError::Internal(_) => GetError::KvGetError(e),
        })?;

        Ok(serde_json::from_slice(&value_bytes).map_err(GetError::ValueDecodeError)?)
    }

    fn get_interim_transcript_hash(
        &self,
        group_id: &<Self::Types as storage::Types<V1>>::GroupId,
    ) -> Result<<Self::Types as storage::Types<V1>>::InterimTranscriptHash, Self::GetError> {
        let store = self.read_get()?;

        let key = Key::<Types>::InterimTranscriptHash(group_id)
            .key()
            .map_err(GetError::KeyEncodeError)?;

        let value_bytes = store.get(&key).map_err(|e| match e {
            kv_store::KvGetError::NotFound(key) => GetError::NotFound(key),
            kv_store::KvGetError::Internal(_) => GetError::KvGetError(e),
        })?;

        Ok(serde_json::from_slice(&value_bytes).map_err(GetError::ValueDecodeError)?)
    }

    fn get_confirmation_tag(
        &self,
        group_id: &<Self::Types as storage::Types<V1>>::GroupId,
    ) -> Result<<Self::Types as storage::Types<V1>>::ConfirmationTag, Self::GetError> {
        let store = self.read_get()?;

        let key = Key::<Types>::ConfirmationTag(group_id)
            .key()
            .map_err(GetError::KeyEncodeError)?;

        let value_bytes = store.get(&key).map_err(|e| match e {
            kv_store::KvGetError::NotFound(key) => GetError::NotFound(key),
            kv_store::KvGetError::Internal(_) => GetError::KvGetError(e),
        })?;

        Ok(serde_json::from_slice(&value_bytes).map_err(GetError::ValueDecodeError)?)
    }

    fn signature_key_pair(
        &self,
        public_key: &<Self::Types as storage::Types<V1>>::SignaturePublicKey,
    ) -> Result<<Self::Types as storage::Types<V1>>::SignatureKeyPair, Self::GetError> {
        todo!()
    }
}

impl<KvStore: kv_store::KvStore, Types: storage::Types<V1>> KvStoreStorage<KvStore, Types> {
    fn read_get(&self) -> Result<RwLockReadGuard<KvStore>, GetError<KvStore::InternalError>> {
        self.0.read().map_err(|_| GetError::LockPoisonedError)
    }
}

impl<KvStore: kv_store::KvStore, Types: storage::Types<V1>> KvStoreStorage<KvStore, Types> {
    fn read_update(&self) -> Result<RwLockReadGuard<KvStore>, UpdateError<KvStore::InternalError>> {
        self.0.read().map_err(|_| UpdateError::LockPoisonedError)
    }
}

impl<KvStore: kv_store::KvStore, Types: storage::Types<V1>> KvStoreStorage<KvStore, Types> {
    fn write_update(
        &self,
    ) -> Result<RwLockWriteGuard<KvStore>, UpdateError<KvStore::InternalError>> {
        self.0.write().map_err(|_| UpdateError::LockPoisonedError)
    }
}
