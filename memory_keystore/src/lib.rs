use openmls_traits::{
    key_store::{MlsEntity, OpenMlsKeyStore},
    storage::{self, GetError, Key, StorageProvider, Update, UpdateError},
};
use std::{collections::HashMap, marker::PhantomData, sync::RwLock};

#[derive(Debug, Default)]
pub struct MemoryKeyStore<Types: Default> {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
    phantom: PhantomData<Types>,
}

impl<Types: Default> OpenMlsKeyStore for MemoryKeyStore<Types> {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = MemoryKeyStoreError;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let value = serde_json::to_vec(v).map_err(|_| MemoryKeyStoreError::SerializationError)?;
        // We unwrap here, because this is the only function claiming a write
        // lock on `credential_bundles`. It only holds the lock very briefly and
        // should not panic during that period.
        let mut values = self.values.write().unwrap();
        values.insert(k.to_vec(), value);
        Ok(())
    }

    /// Read and return a value stored for ID `k` that implements the
    /// [`FromKeyStoreValue`] trait for deserialization.
    ///
    /// Returns [`None`] if no value is stored for `k` or reading fails.
    fn read<V: MlsEntity>(&self, k: &[u8]) -> Option<V> {
        // We unwrap here, because the two functions claiming a write lock on
        // `init_key_package_bundles` (this one and `generate_key_package_bundle`) only
        // hold the lock very briefly and should not panic during that period.
        let values = self.values.read().unwrap();
        if let Some(value) = values.get(k) {
            serde_json::from_slice(value).ok()
        } else {
            None
        }
    }

    /// Delete a value stored for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn delete<V: MlsEntity>(&self, k: &[u8]) -> Result<(), Self::Error> {
        // We just delete both ...
        let mut values = self.values.write().unwrap();
        values.remove(k);
        Ok(())
    }
}

/// Errors thrown by the key store.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemoryKeyStoreError {
    #[error("The key store does not allow storing serialized values.")]
    UnsupportedValueTypeBytes,
    #[error("Updating is not supported by this key store.")]
    UnsupportedMethod,
    #[error("Error serializing value.")]
    SerializationError,
}

impl GetError for MemoryKeyStoreError {
    fn error_kind(&self) -> storage::GetErrorKind {
        todo!()
    }
}

impl UpdateError for MemoryKeyStoreError {
    fn error_kind(&self) -> storage::UpdateErrorKind {
        todo!()
    }
}

pub const V1: usize = 1;

impl<Types: storage::Types<1>> StorageProvider<1> for MemoryKeyStore<Types> {
    type GetError = MemoryKeyStoreError;
    type UpdateError = MemoryKeyStoreError;
    type Types = Types;

    fn apply_update(&self, update: Update<1, Self::Types>) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        match update {
            Update::QueueProposal(group_id, proposal_ref, queued_proposal) => {
                let mut key = b"QueueProposal".to_vec();
                key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());

                let mut value = serde_json::to_vec(&proposal_ref).unwrap();
                value.extend_from_slice(&serde_json::to_vec(&queued_proposal).unwrap());

                values.insert(key, value);
            }
            Update::WriteTreeSync(group_id, tree) => {
                let mut key = b"Tree".to_vec();
                key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
                let value = serde_json::to_vec(&tree).unwrap();

                values.insert(key, value);
            }
            Update::WriteGroupContext(group_id, context) => {
                let mut key = b"GroupContext".to_vec();
                key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
                let value = serde_json::to_vec(&context).unwrap();

                values.insert(key, value);
            }
            Update::WriteInterimTranscriptHash(group_id, interim_transcript_hash) => {
                let mut key = b"InterimTranscriptHash".to_vec();
                key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
                let value = serde_json::to_vec(&interim_transcript_hash).unwrap();

                values.insert(key, value);
            }
            Update::WriteConfirmationTag(group_id, confirmation_tag) => {
                let mut key = b"ConfirmationTag".to_vec();
                key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
                let value = serde_json::to_vec(&confirmation_tag).unwrap();

                values.insert(key, value);
            }
        }
        Ok(())
    }

    fn apply_updates(&self, update: Vec<Update<1, Self::Types>>) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn get_queued_proposal_refs(
        &self,
        group_id: &<Self::Types as storage::Types<1>>::GroupId,
    ) -> Result<Vec<<Self::Types as storage::Types<1>>::ProposalRef>, Self::GetError> {
        todo!()
    }

    fn get_queued_proposals(
        &self,
        group_id: &<Self::Types as storage::Types<1>>::GroupId,
    ) -> Result<Vec<<Self::Types as storage::Types<1>>::QueuedProposal>, Self::GetError> {
        todo!()
    }

    fn get_treesync(
        &self,
        group_id: &<Self::Types as storage::Types<1>>::GroupId,
    ) -> Result<<Self::Types as storage::Types<1>>::TreeSync, Self::GetError> {
        todo!()
    }

    fn get_group_context(
        &self,
        group_id: &<Self::Types as storage::Types<1>>::GroupId,
    ) -> Result<<Self::Types as storage::Types<1>>::GroupContext, Self::GetError> {
        todo!()
    }

    fn get_interim_transcript_hash(
        &self,
        group_id: &<Self::Types as storage::Types<1>>::GroupId,
    ) -> Result<<Self::Types as storage::Types<1>>::InterimTranscriptHash, Self::GetError> {
        todo!()
    }

    fn get_confirmation_tag(
        &self,
        group_id: &<Self::Types as storage::Types<1>>::GroupId,
    ) -> Result<<Self::Types as storage::Types<1>>::ConfirmationTag, Self::GetError> {
        todo!()
    }
}
