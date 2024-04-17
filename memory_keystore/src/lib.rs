use openmls_traits::{
    key_store::{MlsEntity, OpenMlsKeyStore},
    storage::{self, *},
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::RwLock};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryKeyStore {
    fn write<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: &[u8],
    ) -> Result<(), <Self as OpenMlsKeyStore>::Error> {
        let mut values = self.values.write().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(&serde_json::to_vec(key).unwrap());
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));
        let value = serde_json::to_vec(value).unwrap();

        values.insert(storage_key, value);
        Ok(())
    }

    fn read<const VERSION: u16, V: Entity<VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<V, <Self as OpenMlsKeyStore>::Error> {
        let mut values = self.values.read().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(&serde_json::to_vec(&key).unwrap());
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        let value = values.get(&storage_key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn delete<const VERSION: u16, V: Entity<VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<V>, <Self as OpenMlsKeyStore>::Error> {
        let mut values = self.values.write().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(&serde_json::to_vec(&storage_key).unwrap());
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        let out = values
            .remove(&storage_key)
            .map(|bytes| serde_json::from_slice(&bytes).unwrap());

        Ok(out)
    }
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
    #[error("Value does not exist.")]
    None,
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

const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
const INIT_KEY_LABEL: &[u8] = b"HpkePrivateKey";
const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
const TREE_LABEL: &[u8] = b"Tree";
const PSK_LABEL: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";

impl StorageProvider<CURRENT_VERSION> for MemoryKeyStore {
    type GetError = MemoryKeyStoreError;
    type UpdateError = MemoryKeyStoreError;
    // type Types = Types;

    fn queue_proposal(
        &self,
        group_id: impl storage::GroupIdKey<CURRENT_VERSION>,
        proposal_ref: impl storage::ProposalRefEntity<CURRENT_VERSION>,
        proposal: impl storage::QueuedProposalEntity<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();

        let mut key = QUEUED_PROPOSAL_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

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
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&proposal_ref).unwrap();
        values.insert(key, value);

        Ok(())
    }

    fn write_tree(
        &self,
        group_id: impl storage::GroupIdKey<CURRENT_VERSION>,
        tree: impl storage::TreeSyncEntity<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        self.write::<CURRENT_VERSION>(
            TREE_LABEL,
            &serde_json::to_vec(&group_id).unwrap(),
            &serde_json::to_vec(&tree).unwrap(),
        )
    }

    fn write_interim_transcript_hash(
        &self,
        group_id: impl storage::GroupIdKey<CURRENT_VERSION>,
        interim_transcript_hash: impl storage::InterimTranscriptHashEntity<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        let mut key = b"InterimTranscriptHash".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&interim_transcript_hash).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_context(
        &self,
        group_id: impl storage::GroupIdKey<CURRENT_VERSION>,
        group_context: impl storage::GroupContextEntity<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        let mut key = b"GroupContext".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&group_context).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_confirmation_tag(
        &self,
        group_id: impl storage::GroupIdKey<CURRENT_VERSION>,
        confirmation_tag: impl storage::ConfirmationTagEntity<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        let mut key = b"ConfirmationTag".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&confirmation_tag).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_signature_key_pair(
        &self,
        public_key: impl storage::SignaturePublicKeyKey<CURRENT_VERSION>,
        key_pair: impl storage::SignatureKeyPairEntity<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();
        let mut key = SIGNATURE_KEY_PAIR_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&key_pair).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn get_queued_proposal_refs<V: ProposalRefEntity<CURRENT_VERSION>>(
        &self,
        group_id: &impl storage::GroupIdKey<CURRENT_VERSION>,
    ) -> Result<Vec<V>, Self::GetError> {
        let values = self.values.read().unwrap();

        let mut key = b"ProposalRef".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        // XXX: This is wrong.
        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(vec![value])
    }

    fn get_queued_proposals<V: storage::QueuedProposalEntity<CURRENT_VERSION>>(
        &self,
        group_id: &impl storage::GroupIdKey<CURRENT_VERSION>,
    ) -> Result<Vec<V>, Self::GetError> {
        let values = self.values.read().unwrap();

        let mut key = QUEUED_PROPOSAL_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(vec![value])
    }

    fn get_treesync<V: storage::TreeSyncEntity<CURRENT_VERSION>>(
        &self,
        group_id: &impl storage::GroupIdKey<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        let values = self.values.read().unwrap();

        // XXX: These domain separators should be constants.
        let mut key = b"Tree".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn get_group_context<V: storage::GroupContextEntity<CURRENT_VERSION>>(
        &self,
        group_id: &impl storage::GroupIdKey<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        let values = self.values.read().unwrap();

        let mut key = b"GroupContext".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn get_interim_transcript_hash<V: storage::InterimTranscriptHashEntity<CURRENT_VERSION>>(
        &self,
        group_id: &impl storage::GroupIdKey<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        let values = self.values.read().unwrap();

        let mut key = b"InterimTranscriptHash".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn get_confirmation_tag<V: storage::ConfirmationTagEntity<CURRENT_VERSION>>(
        &self,
        group_id: &impl storage::GroupIdKey<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        let values = self.values.read().unwrap();

        let mut key = b"ConfirmationTag".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn signature_key_pair<V: storage::SignatureKeyPairEntity<CURRENT_VERSION>>(
        &self,
        public_key: &impl storage::SignaturePublicKeyKey<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        let values = self.values.read().unwrap();

        let mut key = SIGNATURE_KEY_PAIR_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn write_init_private_key(
        &self,
        public_key: impl storage::InitKey<CURRENT_VERSION>,
        private_key: impl storage::HpkePrivateKey<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();

        let mut key = INIT_KEY_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&private_key).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_key_package(
        &self,
        hash_ref: impl storage::HashReference<CURRENT_VERSION>,
        key_package: impl storage::KeyPackage<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        let mut values = self.values.write().unwrap();

        let mut key = KEY_PACKAGE_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&hash_ref).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&key_package).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_psk(
        &self,
        psk_id: impl storage::PskKey<CURRENT_VERSION>,
        psk: impl storage::PskBundle<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        self.write::<CURRENT_VERSION>(
            PSK_LABEL,
            &serde_json::to_vec(&psk_id).unwrap(),
            &serde_json::to_vec(&psk).unwrap(),
        )
    }

    fn write_encryption_key_pair(
        &self,
        public_key: impl storage::HpkePublicKey<CURRENT_VERSION>,
        key_pair: impl storage::HpkeKeyPair<CURRENT_VERSION>,
    ) -> Result<(), Self::UpdateError> {
        self.write::<CURRENT_VERSION>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(&public_key).unwrap(),
            &serde_json::to_vec(&key_pair).unwrap(),
        )
    }

    fn init_private_key<V: storage::HpkePrivateKey<CURRENT_VERSION>>(
        &self,
        public_key: impl storage::InitKey<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        let values = self.values.read().unwrap();

        let mut key = INIT_KEY_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = values.get(&key).ok_or(MemoryKeyStoreError::None)?;

        Ok(serde_json::from_slice(value).map_err(|_| MemoryKeyStoreError::SerializationError)?)
    }

    fn key_package<V: storage::KeyPackage<CURRENT_VERSION>>(
        &self,
        hash_ref: impl storage::HashReference<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        self.read(KEY_PACKAGE_LABEL, &serde_json::to_vec(&hash_ref).unwrap())
    }

    fn psk<V: storage::PskBundle<CURRENT_VERSION>>(
        &self,
        psk_id: impl storage::PskKey<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        self.read(PSK_LABEL, &serde_json::to_vec(&psk_id).unwrap())
    }

    fn encryption_key_pair<V: storage::HpkeKeyPair<CURRENT_VERSION>>(
        &self,
        public_key: impl storage::HpkePublicKey<CURRENT_VERSION>,
    ) -> Result<V, Self::GetError> {
        self.read(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(&public_key).unwrap(),
        )
    }

    fn delete_signature_key_pair<V: storage::SignatureKeyPairEntity<CURRENT_VERSION>>(
        &self,
        public_key: &impl storage::SignaturePublicKeyKey<CURRENT_VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        self.delete(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).unwrap(),
        )
    }

    fn delete_init_private_key<V: storage::HpkePrivateKey<CURRENT_VERSION>>(
        &self,
        public_key: impl storage::InitKey<CURRENT_VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        self.delete(INIT_KEY_LABEL, &serde_json::to_vec(&public_key).unwrap())
    }

    fn delete_encryption_key_pair<V: storage::HpkeKeyPair<CURRENT_VERSION>>(
        &self,
        public_key: impl storage::HpkePublicKey<CURRENT_VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        self.delete(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(&public_key).unwrap(),
        )
    }

    fn delete_key_package<V: storage::KeyPackage<CURRENT_VERSION>>(
        &self,
        hash_ref: impl storage::HashReference<CURRENT_VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        self.delete(KEY_PACKAGE_LABEL, &serde_json::to_vec(&hash_ref).unwrap())
    }

    fn delete_psk<V: storage::PskBundle<CURRENT_VERSION>>(
        &self,
        psk_id: impl storage::PskKey<CURRENT_VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        self.delete(PSK_LABEL, &serde_json::to_vec(&psk_id).unwrap())
    }
}

#[cfg(feature = "test-utils")]
impl StorageProvider<V_TEST> for MemoryKeyStore {
    type GetError = MemoryKeyStoreError;
    type UpdateError = MemoryKeyStoreError;

    fn queue_proposal(
        &self,
        group_id: impl GroupIdKey<V_TEST>,
        proposal_ref: impl ProposalRefEntity<V_TEST>,
        proposal: impl QueuedProposalEntity<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_tree(
        &self,
        group_id: impl GroupIdKey<V_TEST>,
        tree: impl TreeSyncEntity<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_interim_transcript_hash(
        &self,
        group_id: impl GroupIdKey<V_TEST>,
        interim_transcript_hash: impl InterimTranscriptHashEntity<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_context(
        &self,
        group_id: impl GroupIdKey<V_TEST>,
        group_context: impl GroupContextEntity<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_confirmation_tag(
        &self,
        group_id: impl GroupIdKey<V_TEST>,
        confirmation_tag: impl ConfirmationTagEntity<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_signature_key_pair(
        &self,
        public_key: impl SignaturePublicKeyKey<V_TEST>,
        signature_key_pair: impl SignatureKeyPairEntity<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_init_private_key(
        &self,
        public_key: impl InitKey<V_TEST>,
        private_key: impl HpkePrivateKey<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_encryption_key_pair(
        &self,
        public_key: impl HpkePublicKey<V_TEST>,
        key_pair: impl HpkeKeyPair<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_key_package(
        &self,
        hash_ref: impl HashReference<V_TEST>,
        key_package: impl KeyPackage<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_psk(
        &self,
        psk_id: impl PskKey<V_TEST>,
        psk: impl PskBundle<V_TEST>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn get_queued_proposal_refs<V: ProposalRefEntity<V_TEST>>(
        &self,
        group_id: &impl GroupIdKey<V_TEST>,
    ) -> Result<Vec<V>, Self::GetError> {
        todo!()
    }

    fn get_queued_proposals<V: QueuedProposalEntity<V_TEST>>(
        &self,
        group_id: &impl GroupIdKey<V_TEST>,
    ) -> Result<Vec<V>, Self::GetError> {
        todo!()
    }

    fn get_treesync<V: TreeSyncEntity<V_TEST>>(
        &self,
        group_id: &impl GroupIdKey<V_TEST>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn get_group_context<V: GroupContextEntity<V_TEST>>(
        &self,
        group_id: &impl GroupIdKey<V_TEST>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn get_interim_transcript_hash<V: InterimTranscriptHashEntity<V_TEST>>(
        &self,
        group_id: &impl GroupIdKey<V_TEST>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn get_confirmation_tag<V: ConfirmationTagEntity<V_TEST>>(
        &self,
        group_id: &impl GroupIdKey<V_TEST>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn signature_key_pair<V: SignatureKeyPairEntity<V_TEST>>(
        &self,
        public_key: &impl SignaturePublicKeyKey<V_TEST>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn init_private_key<V: HpkePrivateKey<V_TEST>>(
        &self,
        public_key: impl InitKey<V_TEST>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn encryption_key_pair<V: HpkeKeyPair<V_TEST>>(
        &self,
        public_key: impl HpkePublicKey<V_TEST>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn key_package<V: KeyPackage<V_TEST>>(
        &self,
        hash_ref: impl HashReference<V_TEST>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn psk<V: PskBundle<V_TEST>>(&self, psk_id: impl PskKey<V_TEST>) -> Result<V, Self::GetError> {
        todo!()
    }

    fn delete_signature_key_pair<V: SignatureKeyPairEntity<V_TEST>>(
        &self,
        public_key: &impl SignaturePublicKeyKey<V_TEST>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn delete_init_private_key<V: HpkePrivateKey<V_TEST>>(
        &self,
        public_key: impl InitKey<V_TEST>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn delete_encryption_key_pair<V: HpkeKeyPair<V_TEST>>(
        &self,
        public_key: impl HpkePublicKey<V_TEST>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn delete_key_package<V: KeyPackage<V_TEST>>(
        &self,
        hash_ref: impl HashReference<V_TEST>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn delete_psk<V: PskBundle<V_TEST>>(
        &self,
        psk_id: impl PskKey<V_TEST>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }
}
