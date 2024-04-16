use openmls_traits::{
    key_store::{MlsEntity, OpenMlsKeyStore},
    storage::{self, GetError, ProposalRefEntity, StorageProvider, UpdateError},
};
use std::{collections::HashMap, sync::RwLock};

#[derive(Debug, Default)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl OpenMlsKeyStore for MemoryKeyStore {
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

impl StorageProvider<1> for MemoryKeyStore {
    type GetError = MemoryKeyStoreError;
    type UpdateError = MemoryKeyStoreError;
    // type Types = Types;

    fn queue_proposal(
        &self,
        group_id: impl storage::GroupIdKey<1>,
        proposal_ref: impl storage::ProposalRefEntity<1>,
        proposal: impl storage::QueuedProposalEntity<1>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();

        let mut key = b"QueuedProposal".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));

        let mut proposals = values.get_mut(&key);
        let new_value = serde_json::to_vec(&proposal).unwrap();
        if let Some(proposals) = proposals {
            proposals.extend_from_slice(&new_value); // XXX: this doesn't actually work like this.
        } else {
            values.insert(key, new_value);
        }

        // XXX: actually append
        let mut key = b"ProposalRef".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));
        let value = serde_json::to_vec(&proposal_ref).unwrap();
        values.insert(key, value);

        Ok(())
    }

    fn write_tree(
        &self,
        group_id: impl storage::GroupIdKey<1>,
        tree: impl storage::TreeSyncEntity<1>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();

        let mut key = b"Tree".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));
        let value = serde_json::to_vec(&tree).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_interim_transcript_hash(
        &self,
        group_id: impl storage::GroupIdKey<1>,
        interim_transcript_hash: impl storage::InterimTranscriptHashEntity<1>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        let mut key = b"InterimTranscriptHash".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));
        let value = serde_json::to_vec(&interim_transcript_hash).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_context(
        &self,
        group_id: impl storage::GroupIdKey<1>,
        group_context: impl storage::GroupContextEntity<1>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        let mut key = b"GroupContext".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));
        let value = serde_json::to_vec(&group_context).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_confirmation_tag(
        &self,
        group_id: impl storage::GroupIdKey<1>,
        confirmation_tag: impl storage::ConfirmationTagEntity<1>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        let mut key = b"ConfirmationTag".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));
        let value = serde_json::to_vec(&confirmation_tag).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_signature_key_pair(
        &self,
        public_key: impl storage::SignaturePublicKeyKey<1>,
        key_pair: impl storage::SignatureKeyPairEntity<1>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        let mut key = b"SignatureKeyPair".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));
        let value = serde_json::to_vec(&key_pair).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn get_queued_proposal_refs<V: ProposalRefEntity<1>>(
        &self,
        group_id: &impl storage::GroupIdKey<1>,
    ) -> Result<Vec<V>, Self::GetError> {
        let mut values = self.values.read().unwrap();

        let mut key = b"ProposalRef".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));

        // XXX: This is wrong.
        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(vec![value])
    }

    fn get_queued_proposals<V: storage::QueuedProposalEntity<1>>(
        &self,
        group_id: &impl storage::GroupIdKey<1>,
    ) -> Result<Vec<V>, Self::GetError> {
        let mut values = self.values.read().unwrap();

        let mut key = b"QueuedProposal".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(vec![value])
    }

    fn get_treesync<V: storage::TreeSyncEntity<1>>(
        &self,
        group_id: &impl storage::GroupIdKey<1>,
    ) -> Result<V, Self::GetError> {
        let mut values = self.values.read().unwrap();

        // XXX: These domain separators should be constants.
        let mut key = b"Tree".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn get_group_context<V: storage::GroupContextEntity<1>>(
        &self,
        group_id: &impl storage::GroupIdKey<1>,
    ) -> Result<V, Self::GetError> {
        let mut values = self.values.read().unwrap();

        let mut key = b"GroupContext".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn get_interim_transcript_hash<V: storage::InterimTranscriptHashEntity<1>>(
        &self,
        group_id: &impl storage::GroupIdKey<1>,
    ) -> Result<V, Self::GetError> {
        let mut values = self.values.read().unwrap();

        let mut key = b"InterimTranscriptHash".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn get_confirmation_tag<V: storage::ConfirmationTagEntity<1>>(
        &self,
        group_id: &impl storage::GroupIdKey<1>,
    ) -> Result<V, Self::GetError> {
        let mut values = self.values.read().unwrap();

        let mut key = b"ConfirmationTag".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn signature_key_pair<V: storage::SignatureKeyPairEntity<1>>(
        &self,
        public_key: &impl storage::SignaturePublicKeyKey<1>,
    ) -> Result<V, Self::GetError> {
        let mut values = self.values.read().unwrap();

        let mut key = b"SignatureKeyPair".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(1));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }
}
