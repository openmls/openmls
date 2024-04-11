mod kv_store;
pub mod mem_kv_store;

use std::sync::RwLock;

use mem_kv_store::{KvGetError, KvInsertError};
use openmls_traits::storage::Types as TypesTrait;
use openmls_traits::storage::*;

const V1: usize = 1;

#[derive(Debug, Default)]
pub struct KvStoreStorage<KvStore: kv_store::KvStore, Ts: Types<V1>>(RwLock<KvStore>, Ts);

#[derive(Debug)]
pub enum KvStorageGetError<InternalError> {
    NotFound(Vec<u8>),
    KeyEncodeError(serde_json::Error),
    ValueDecodeError(serde_json::Error),
    KvGetError(KvGetError<InternalError>),
    LockPoisonedError,
}

#[derive(Debug)]
pub enum KvStorageUpdateError<InternalError> {
    KeyEncodeError(serde_json::Error),
    ValueEncodeError(serde_json::Error),
    ValueDecodeError(serde_json::Error),
    KvInsertError(KvInsertError<InternalError>),
    GetError(KvStorageGetError<InternalError>),
    LockPoisonedError,
}

enum Key<'a, Types: TypesTrait<V1>> {
    QueuedProposal(&'a Types::GroupId, &'a Types::ProposalRef),
    QueuedProposalsRefList(&'a Types::GroupId),
    TreeSync(&'a Types::GroupId),
}

impl<'a, Types: TypesTrait<V1>> Key<'a, Types> {
    fn domain_prefix(&self) -> [u8; 2] {
        match self {
            Key::QueuedProposal(_, _) => [0, 0],
            Key::QueuedProposalsRefList(_) => [0, 1],
            Key::TreeSync(_) => [0, 2],
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
        }

        Ok(out)
    }
}

impl<'a, Types: TypesTrait<1>> From<&'a Update<1, Types>> for Key<'a, Types> {
    fn from(value: &'a Update<1, Types>) -> Self {
        match value {
            Update::QueueProposal(group_id, proposal_ref, _) => {
                Self::QueuedProposal(group_id, proposal_ref)
            }
            Update::WriteTreeSync(group_id, _) => Self::TreeSync(group_id),
        }
    }
}

impl<KvStore: kv_store::KvStore, Types: TypesTrait<V1>> StorageProvider<V1>
    for KvStoreStorage<KvStore, Types>
{
    type Types = Types;
    type GetErrorSource = KvStorageGetError<KvStore::InternalError>;
    type UpdateErrorSource = KvStorageUpdateError<KvStore::InternalError>;

    fn apply_update(
        &self,
        update: Update<V1, Types>,
    ) -> Result<(), UpdateError<Self::UpdateErrorSource>> {
        let mut store = self
            .0
            .write()
            .map_err(|_| KvStorageUpdateError::LockPoisonedError)?;
        let key = Key::<Types>::from(&update)
            .key()
            .map_err(KvStorageUpdateError::KeyEncodeError)?;

        match update {
            Update::QueueProposal(group_id, proposal_ref, queued_proposal) => {
                let proposal_key = key;
                let proposal_refs_key = Key::<Types>::QueuedProposalsRefList(&group_id)
                    .key()
                    .map_err(KvStorageUpdateError::KeyEncodeError)?;

                let proposal_value = serde_json::to_vec(&queued_proposal)
                    .map_err(KvStorageUpdateError::ValueEncodeError)?;

                let mut proposal_refs: Vec<_> =
                    match StorageProvider::get_queued_proposal_refs(self, &group_id) {
                        Ok(proposal_refs) => Ok(proposal_refs),
                        Err(GetError {
                            kind: GetErrorKind::NotFound,
                            ..
                        }) => Ok(vec![]),
                        Err(GetError { kind, source }) => {
                            let kind = match kind {
                                GetErrorKind::NotFound => unreachable!(),
                                GetErrorKind::Encoding => UpdateErrorKind::Encoding,
                                GetErrorKind::Internal => UpdateErrorKind::Internal,
                                GetErrorKind::LockPoisoned => UpdateErrorKind::LockPoisoned,
                            };
                            let source = KvStorageUpdateError::GetError(source);

                            Err(UpdateError { kind, source })
                        }
                    }?;

                proposal_refs.push(proposal_ref);

                let proposal_refs_bytes = serde_json::to_vec(&proposal_refs)
                    .map_err(KvStorageUpdateError::ValueEncodeError)?;

                store
                    .insert(proposal_refs_key, proposal_refs_bytes)
                    .map_err(KvStorageUpdateError::KvInsertError)?;

                store
                    .insert(proposal_key, proposal_value)
                    .map_err(KvStorageUpdateError::KvInsertError)?;
            }
            Update::WriteTreeSync(_group_id, tree_sync) => {
                let value_bytes = serde_json::to_vec(&tree_sync)
                    .map_err(KvStorageUpdateError::ValueEncodeError)?;

                store
                    .insert(key, value_bytes)
                    .map_err(KvStorageUpdateError::KvInsertError)?;
            }
        }

        Ok(())
    }

    // TODO: take lock at the start and then iterate
    fn apply_updates(
        &self,
        updates: Vec<Update<V1, Types>>,
    ) -> Result<(), UpdateError<Self::UpdateErrorSource>> {
        for update in updates {
            self.apply_update(update)?
        }

        Ok(())
    }

    fn get_queued_proposals(
        &self,
        group_id: &Types::GroupId,
    ) -> Result<Vec<Types::QueuedProposal>, GetError<Self::GetErrorSource>> {
        let store = self
            .0
            .read()
            .map_err(|_| KvStorageGetError::LockPoisonedError)?;

        StorageProvider::get_queued_proposal_refs(self, group_id)?
            .into_iter()
            .map(|proposal_ref| {
                let proposal_key = Key::<Types>::QueuedProposal(group_id, &proposal_ref)
                    .key()
                    .map_err(|e| GetError {
                        kind: GetErrorKind::Encoding,
                        source: KvStorageGetError::KeyEncodeError(e),
                    })?;
                let value_bytes = store.get(&proposal_key).map_err(|e| match e {
                    kv_store::KvGetError::NotFound(key) => GetError {
                        kind: GetErrorKind::NotFound,
                        source: KvStorageGetError::NotFound(key),
                    },
                    kv_store::KvGetError::Internal(_) => GetError {
                        kind: GetErrorKind::Internal,
                        source: KvStorageGetError::KvGetError(e),
                    },
                })?;

                serde_json::from_slice(&value_bytes).map_err(|e| GetError {
                    kind: GetErrorKind::Encoding,
                    source: KvStorageGetError::ValueDecodeError(e),
                })
            })
            .collect()
    }

    fn get_queued_proposal_refs(
        &self,
        group_id: &Types::GroupId,
    ) -> Result<Vec<Types::ProposalRef>, GetError<Self::GetErrorSource>> {
        let store = self
            .0
            .read()
            .map_err(|_| KvStorageGetError::LockPoisonedError)?;

        let key = Key::<Types>::QueuedProposalsRefList(group_id)
            .key()
            .map_err(KvStorageGetError::KeyEncodeError)?;

        let value_bytes = store.get(&key).map_err(|e| match e {
            kv_store::KvGetError::NotFound(key) => KvStorageGetError::NotFound(key),
            kv_store::KvGetError::Internal(_) => KvStorageGetError::KvGetError(e),
        })?;

        Ok(serde_json::from_slice(&value_bytes).map_err(KvStorageGetError::ValueDecodeError)?)
    }

    fn get_treesync(
        &self,
        group_id: &<Self::Types as TypesTrait<V1>>::GroupId,
    ) -> Result<<Self::Types as TypesTrait<V1>>::TreeSync, GetError<Self::GetErrorSource>> {
        let store = self
            .0
            .read()
            .map_err(|_| KvStorageGetError::LockPoisonedError)?;

        let key = Key::<Types>::QueuedProposalsRefList(group_id)
            .key()
            .map_err(KvStorageGetError::KeyEncodeError)?;

        let value_bytes = store.get(&key).map_err(|e| match e {
            kv_store::KvGetError::NotFound(key) => KvStorageGetError::NotFound(key),
            kv_store::KvGetError::Internal(_) => KvStorageGetError::KvGetError(e),
        })?;

        Ok(serde_json::from_slice(&value_bytes).map_err(KvStorageGetError::ValueDecodeError)?)
    }
}

impl<E> From<KvStorageGetError<E>> for GetError<KvStorageGetError<E>> {
    fn from(source: KvStorageGetError<E>) -> Self {
        let kind = match &source {
            KvStorageGetError::KeyEncodeError(_) | KvStorageGetError::ValueDecodeError(_) => {
                GetErrorKind::Encoding
            }
            KvStorageGetError::NotFound(_) => GetErrorKind::NotFound,
            KvStorageGetError::KvGetError(err) => match err {
                KvGetError::NotFound(_) => GetErrorKind::NotFound,
                KvGetError::Internal(_) => GetErrorKind::Internal,
            },
            KvStorageGetError::LockPoisonedError => GetErrorKind::LockPoisoned,
        };

        GetError { kind, source }
    }
}

impl<E> From<KvStorageUpdateError<E>> for UpdateError<KvStorageUpdateError<E>> {
    fn from(source: KvStorageUpdateError<E>) -> Self {
        let kind = match &source {
            KvStorageUpdateError::KeyEncodeError(_)
            | KvStorageUpdateError::ValueEncodeError(_)
            | KvStorageUpdateError::ValueDecodeError(_) => UpdateErrorKind::Encoding,
            KvStorageUpdateError::KvInsertError(_) | KvStorageUpdateError::GetError(_) => {
                UpdateErrorKind::Internal
            }
            KvStorageUpdateError::LockPoisonedError => UpdateErrorKind::LockPoisoned,
        };

        UpdateError { kind, source }
    }
}
