mod kv_store {
    pub trait KvStore {
        type InternalError: core::fmt::Debug;

        fn get(&self, key: &[u8]) -> Result<Vec<u8>, KvGetError<Self::InternalError>>;
        fn insert(
            &mut self,
            key: Vec<u8>,
            value: Vec<u8>,
        ) -> Result<(), KvInsertError<Self::InternalError>>;
        fn delete(&mut self, key: &[u8]) -> Result<(), KvDeleteError<Self::InternalError>>;
    }

    #[derive(Debug)]
    pub enum Infallible {}

    #[derive(Debug)]
    pub enum KvGetError<InternalError> {
        NotFound(Vec<u8>),
        Internal(InternalError),
    }

    #[derive(Debug)]
    pub enum KvInsertError<InternalError> {
        AlreadyExists(Vec<u8>, Vec<u8>),
        Internal(InternalError),
    }

    #[derive(Debug)]
    pub enum KvDeleteError<InternalError> {
        NotFound(Vec<u8>),
        Internal(InternalError),
    }
}

pub mod mem_kv_store {
    pub use super::kv_store::*;

    #[derive(Default)]
    pub struct HashMapKv(std::collections::HashMap<Vec<u8>, Vec<u8>>);

    impl KvStore for HashMapKv {
        type InternalError = Infallible;

        fn get(&self, key: &[u8]) -> Result<Vec<u8>, KvGetError<Infallible>> {
            self.0
                .get(key)
                .cloned()
                .ok_or(KvGetError::NotFound(key.to_vec()))
        }

        fn insert(
            &mut self,
            key: Vec<u8>,
            value: Vec<u8>,
        ) -> Result<(), KvInsertError<Infallible>> {
            match self.0.insert(key.clone(), value) {
                Some(old_value) => Err(KvInsertError::AlreadyExists(key, old_value)),
                None => Ok(()),
            }
        }

        fn delete(&mut self, key: &[u8]) -> Result<(), KvDeleteError<Infallible>> {
            match self.0.remove(key) {
                Some(_) => Ok(()),
                None => Err(KvDeleteError::NotFound(key.to_vec())),
            }
        }
    }
}

use mem_kv_store::{KvGetError, KvInsertError};
use openmls_traits::storage::Types as TypesTrait;
use openmls_traits::storage::*;

const V1: usize = 1;

struct KvStoreStorage<KvStore: kv_store::KvStore, Types: TypesTrait<V1>>(KvStore, Types);

#[derive(Debug)]
pub enum KvStorageGetError<InternalError> {
    NotFound(Vec<u8>),
    KeyEncodeError(serde_json::Error),
    ValueDecodeError(serde_json::Error),
    KvGetError(KvGetError<InternalError>),
}

#[derive(Debug)]
pub enum KvStorageUpdateError<InternalError> {
    KeyEncodeError(serde_json::Error),
    ValueEncodeError(serde_json::Error),
    KvInsertError(KvInsertError<InternalError>),
}

enum Key<Types: TypesTrait<V1>> {
    QueuedProposal(Types::GroupId, Types::ProposalRef),
    QueuedProposalsRefList(Types::GroupId),
}

impl<Types: TypesTrait<V1>> Key<Types> {
    fn domain_prefix(&self) -> [u8; 2] {
        match self {
            Self::QueuedProposal(_, _) => [0, 0],
        }
    }

    fn key(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut out = Vec::with_capacity(256);

        match self {
            Self::QueuedProposal(group_id, proposal_ref) => {
                out.extend_from_slice(&self.domain_prefix());
                // TODO: This is not necessarily injective! Use better encoding
                //          Though tbf it's mostly a problem if both are numbers I think
                serde_json::to_writer(&mut out, group_id)?;
                serde_json::to_writer(&mut out, proposal_ref)?;
            }
        }

        Ok(out)
    }
}

// TODO: move version into generics
impl<KvStore: kv_store::KvStore, Types: TypesTrait<V1>> Storage<V1>
    for KvStoreStorage<KvStore, Types>
{
    type Types = Types;
    type GetErrorSource = KvStorageGetError<KvStore::InternalError>;
    type UpdateErrorSource = KvStorageUpdateError<KvStore::InternalError>;

    fn apply_update(
        &mut self,
        update: Update<V1, Self::Types>,
    ) -> Result<(), UpdateError<Self::UpdateErrorSource>> {
        match update {
            Update::QueueProposal(group_id, proposal_ref, queued_proposal) => {
                let proposal_key = Key::<Types>::QueuedProposal(group_id, proposal_ref)
                    .key()
                    .map_err(|e| UpdateError {
                        kind: UpdateErrorKind::Internal,
                        source: KvStorageUpdateError::KeyEncodeError(e),
                    })?;

                let proposal_value =
                    serde_json::to_vec(&queued_proposal).map_err(|e| UpdateError {
                        kind: UpdateErrorKind::Internal,
                        source: KvStorageUpdateError::ValueEncodeError(e),
                    })?;

                self.0
                    .insert(proposal_key, proposal_value)
                    .map_err(|err| UpdateError {
                        kind: UpdateErrorKind::Internal,
                        source: KvStorageUpdateError::KvInsertError(err),
                    })
            }
        }
    }

    fn apply_updates(
        &mut self,
        updates: Vec<Update<V1, Self::Types>>,
    ) -> Result<(), UpdateError<Self::UpdateErrorSource>> {
        for update in updates {
            self.apply_update(update)?
        }

        Ok(())
    }

    fn get_queued_proposals(
        &self,
        group_id: Types::GroupId,
    ) -> Result<Vec<Types::QueuedProposal>, GetError<Self::GetErrorSource>> {
        todo!()
    }

    fn get_queued_proposal_refs(
        &self,
        group_id: Types::GroupId,
    ) -> Result<Vec<Types::ProposalRef>, GetError<Self::GetErrorSource>> {
        let key = Key::<Types>::QueuedProposalsRefList(group_id)
            .key()
            .map_err(|e| GetError {
                kind: GetErrorKind::Encoding,
                source: KvStorageGetError::KeyEncodeError(e),
            })?;

        let value_bytes = self.0.get(&key).map_err(|e| match e {
            kv_store::KvGetError::NotFound(key) => GetError {
                kind: GetErrorKind::NotFound,
                source: KvStorageGetError::NotFound(key),
            },
            kv_store::KvGetError::Internal(_) => GetError {
                kind: GetErrorKind::Internal,
                source: KvStorageGetError::KvGetError(e),
            },
        })?;

        let value: Vec<Types::ProposalRef> =
            serde_json::from_slice(&value_bytes).map_err(|e| GetError {
                kind: GetErrorKind::Encoding,
                source: KvStorageGetError::ValueDecodeError(e),
            })?;

        Ok(value)
    }
}
