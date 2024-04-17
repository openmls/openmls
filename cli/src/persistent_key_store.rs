use openmls_traits::{
    key_store::{MlsEntity, OpenMlsKeyStore},
    storage::{GetError, StorageProvider, UpdateError},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufReader, BufWriter},
    path::PathBuf,
    sync::RwLock,
};

use super::file_helpers;

#[derive(Debug, Default)]
pub struct PersistentKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializableKeyStore {
    values: HashMap<String, String>,
}

impl GetError for PersistentKeyStoreError {
    fn error_kind(&self) -> openmls_traits::storage::GetErrorKind {
        todo!()
    }
}

impl UpdateError for PersistentKeyStoreError {
    fn error_kind(&self) -> openmls_traits::storage::UpdateErrorKind {
        todo!()
    }
}

impl<const VERSION: u16> StorageProvider<VERSION> for PersistentKeyStore {
    type GetError = PersistentKeyStoreError;

    type UpdateError = PersistentKeyStoreError;

    fn queue_proposal(
        &self,
        group_id: impl openmls_traits::storage::GroupIdKey<VERSION>,
        proposal_ref: impl openmls_traits::storage::ProposalRefEntity<VERSION>,
        proposal: impl openmls_traits::storage::QueuedProposalEntity<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_tree(
        &self,
        group_id: impl openmls_traits::storage::GroupIdKey<VERSION>,
        tree: impl openmls_traits::storage::TreeSyncEntity<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_interim_transcript_hash(
        &self,
        group_id: impl openmls_traits::storage::GroupIdKey<VERSION>,
        interim_transcript_hash: impl openmls_traits::storage::InterimTranscriptHashEntity<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_context(
        &self,
        group_id: impl openmls_traits::storage::GroupIdKey<VERSION>,
        group_context: impl openmls_traits::storage::GroupContextEntity<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_confirmation_tag(
        &self,
        group_id: impl openmls_traits::storage::GroupIdKey<VERSION>,
        confirmation_tag: impl openmls_traits::storage::ConfirmationTagEntity<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_signature_key_pair(
        &self,
        public_key: impl openmls_traits::storage::SignaturePublicKeyKey<VERSION>,
        signature_key_pair: impl openmls_traits::storage::SignatureKeyPairEntity<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn get_queued_proposal_refs<V: openmls_traits::storage::ProposalRefEntity<VERSION>>(
        &self,
        group_id: &impl openmls_traits::storage::GroupIdKey<VERSION>,
    ) -> Result<Vec<V>, Self::GetError> {
        todo!()
    }

    fn get_queued_proposals<V: openmls_traits::storage::QueuedProposalEntity<VERSION>>(
        &self,
        group_id: &impl openmls_traits::storage::GroupIdKey<VERSION>,
    ) -> Result<Vec<V>, Self::GetError> {
        todo!()
    }

    fn get_treesync<V: openmls_traits::storage::TreeSyncEntity<VERSION>>(
        &self,
        group_id: &impl openmls_traits::storage::GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn get_group_context<V: openmls_traits::storage::GroupContextEntity<VERSION>>(
        &self,
        group_id: &impl openmls_traits::storage::GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn get_interim_transcript_hash<
        V: openmls_traits::storage::InterimTranscriptHashEntity<VERSION>,
    >(
        &self,
        group_id: &impl openmls_traits::storage::GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn get_confirmation_tag<V: openmls_traits::storage::ConfirmationTagEntity<VERSION>>(
        &self,
        group_id: &impl openmls_traits::storage::GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn signature_key_pair<V: openmls_traits::storage::SignatureKeyPairEntity<VERSION>>(
        &self,
        public_key: &impl openmls_traits::storage::SignaturePublicKeyKey<VERSION>,
    ) -> Result<V, Self::GetError> {
        todo!()
    }

    fn write_init_private_key(
        &self,
        public_key: impl openmls_traits::storage::InitKey<VERSION>,
        private_key: impl openmls_traits::storage::HpkePrivateKey<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_psk(
        &self,
        psk_id: impl openmls_traits::storage::PskKey<VERSION>,
        psk: impl openmls_traits::storage::PskBundle<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_encryption_key_pair(
        &self,
        public_key: impl openmls_traits::storage::HpkePublicKey<VERSION>,
        key_pair: impl openmls_traits::storage::HpkeKeyPairEntity<VERSION>,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn init_private_key<V: openmls_traits::storage::HpkePrivateKey<VERSION>>(
        &self,
        public_key: impl openmls_traits::storage::InitKey<VERSION>,
    ) -> Result<V, Self::UpdateError> {
        todo!()
    }

    fn key_package<V: openmls_traits::storage::KeyPackage<VERSION>>(
        &self,
        hash_ref: impl openmls_traits::storage::HashReference<VERSION>,
    ) -> Result<V, Self::UpdateError> {
        todo!()
    }

    fn psk<V: openmls_traits::storage::PskBundle<VERSION>>(
        &self,
        psk_id: impl openmls_traits::storage::PskKey<VERSION>,
    ) -> Result<V, Self::UpdateError> {
        todo!()
    }

    fn encryption_key_pair<V: openmls_traits::storage::HpkeKeyPairEntity<VERSION>>(
        &self,
        public_key: impl openmls_traits::storage::HpkePublicKey<VERSION>,
    ) -> Result<V, Self::UpdateError> {
        todo!()
    }

    fn delete_signature_key_pair<V: openmls_traits::storage::SignatureKeyPairEntity<VERSION>>(
        &self,
        public_key: &impl openmls_traits::storage::SignaturePublicKeyKey<VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn delete_init_private_key<V: openmls_traits::storage::HpkePrivateKey<VERSION>>(
        &self,
        public_key: impl openmls_traits::storage::InitKey<VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn delete_encryption_key_pair<V: openmls_traits::storage::HpkeKeyPairEntity<VERSION>>(
        &self,
        public_key: impl openmls_traits::storage::HpkePublicKey<VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn delete_key_package<V: openmls_traits::storage::KeyPackage<VERSION>>(
        &self,
        hash_ref: impl openmls_traits::storage::HashReference<VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn delete_psk<V: openmls_traits::storage::PskBundle<VERSION>>(
        &self,
        psk_id: impl openmls_traits::storage::PskKey<VERSION>,
    ) -> Result<Option<V>, Self::GetError> {
        todo!()
    }

    fn group_state<
        GroupState: openmls_traits::storage::GroupStateEntity<VERSION>,
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupState, Self::UpdateError> {
        todo!()
    }

    fn write_group_state<
        GroupState: openmls_traits::storage::GroupStateEntity<VERSION>,
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: GroupState,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn delete_group_state<GroupId: openmls_traits::storage::GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn message_secrets<
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
        MessageSecrets: openmls_traits::storage::MessageSecretsEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<MessageSecrets, Self::GetError> {
        todo!()
    }

    fn delete_message_secrets<GroupId: openmls_traits::storage::GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn resumption_psk_store<
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
        ResumptionPskStore: openmls_traits::storage::ResumptionPskStoreEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<ResumptionPskStore, Self::GetError> {
        todo!()
    }

    fn delete_all_resumption_psk_secrets<GroupId: openmls_traits::storage::GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn own_leaf_index<
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
        LeafNodeIndex: openmls_traits::storage::LeafNodeIndexEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<LeafNodeIndex, Self::GetError> {
        todo!()
    }

    fn write_own_leaf_index<
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
        LeafNodeIndex: openmls_traits::storage::LeafNodeIndexEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: LeafNodeIndex,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn delete_own_leaf_index<GroupId: openmls_traits::storage::GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn use_ratchet_tree_extension<GroupId: openmls_traits::storage::GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, Self::GetError> {
        todo!()
    }

    fn set_use_ratchet_tree_extension<GroupId: openmls_traits::storage::GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
        value: bool,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn delete_use_ratchet_tree_extension<GroupId: openmls_traits::storage::GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn group_epoch_secrets<
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
        GroupEpochSecrets: openmls_traits::storage::GroupEpochSecretsEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupEpochSecrets, Self::GetError> {
        todo!()
    }

    fn delete_group_epoch_secrets<GroupId: openmls_traits::storage::GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_key_package<TKeyPackage: openmls_traits::storage::KeyPackage<VERSION>>(
        &self,
        hash_ref: impl openmls_traits::storage::HashReference<VERSION>,
        key_package: TKeyPackage,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_message_secrets<
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
        MessageSecrets: openmls_traits::storage::MessageSecretsEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_resumption_psk_store<
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
        ResumptionPskStore: openmls_traits::storage::ResumptionPskStoreEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }

    fn write_group_epoch_secrets<
        GroupId: openmls_traits::storage::GroupIdKey<VERSION>,
        GroupEpochSecrets: openmls_traits::storage::GroupEpochSecretsEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::UpdateError> {
        todo!()
    }
}

impl OpenMlsKeyStore for PersistentKeyStore {
    /// The error type returned by the [`OpenMlsKeyStore`].
    type Error = PersistentKeyStoreError;

    /// Store a value `v` that implements the [`ToKeyStoreValue`] trait for
    /// serialization for ID `k`.
    ///
    /// Returns an error if storing fails.
    fn store<V: MlsEntity>(&self, k: &[u8], v: &V) -> Result<(), Self::Error> {
        let value =
            serde_json::to_vec(v).map_err(|_| PersistentKeyStoreError::SerializationError)?;
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

impl PersistentKeyStore {
    fn get_file_path(user_name: &String) -> PathBuf {
        file_helpers::get_file_path(&("openmls_cli_".to_owned() + user_name + "_ks.json"))
    }

    fn save_to_file(&self, output_file: &File) -> Result<(), String> {
        let writer = BufWriter::new(output_file);

        let mut ser_ks = SerializableKeyStore::default();
        for (key, value) in &*self.values.read().unwrap() {
            ser_ks
                .values
                .insert(base64::encode(key), base64::encode(value));
        }

        match serde_json::to_writer_pretty(writer, &ser_ks) {
            Ok(()) => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn save(&self, user_name: String) -> Result<(), String> {
        let ks_output_path = PersistentKeyStore::get_file_path(&user_name);

        match File::create(ks_output_path) {
            Ok(output_file) => self.save_to_file(&output_file),
            Err(e) => Err(e.to_string()),
        }
    }

    fn load_from_file(&mut self, input_file: &File) -> Result<(), String> {
        // Prepare file reader.
        let reader = BufReader::new(input_file);

        // Read the JSON contents of the file as an instance of `SerializableKeyStore`.
        match serde_json::from_reader::<BufReader<&File>, SerializableKeyStore>(reader) {
            Ok(ser_ks) => {
                let mut ks_map = self.values.write().unwrap();
                for (key, value) in ser_ks.values {
                    ks_map.insert(base64::decode(key).unwrap(), base64::decode(value).unwrap());
                }
                Ok(())
            }
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn load(&mut self, user_name: String) -> Result<(), String> {
        let ks_input_path = PersistentKeyStore::get_file_path(&user_name);

        match File::open(ks_input_path) {
            Ok(input_file) => self.load_from_file(&input_file),
            Err(e) => Err(e.to_string()),
        }
    }
}

/// Errors thrown by the key store.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum PersistentKeyStoreError {
    #[error("Error serializing value.")]
    SerializationError,
}
