use openmls_traits::storage::StorageProvider;
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
pub struct PersistentStorage {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SerializableKeyStore {
    values: HashMap<String, String>,
}

impl<const VERSION: u16> StorageProvider<VERSION> for PersistentStorage {
    type Error = PersistentKeyStoreError;

    fn queue_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_tree<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_context<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_group_state<
        GroupState: openmls_traits::storage::traits::GroupState<VERSION>,
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        MessageSecrets: openmls_traits::storage::traits::MessageSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_resumption_psk_store<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn set_use_ratchet_tree_extension<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        value: bool,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<VERSION>,
        SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_key_package<
        HashReference: openmls_traits::storage::traits::HashReference<VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_psk<
        PskId: openmls_traits::storage::traits::PskId<VERSION>,
        PskBundle: openmls_traits::storage::traits::PskBundle<VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn queued_proposal_refs<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        todo!()
    }

    fn treesync<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        todo!()
    }

    fn group_context<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        todo!()
    }

    fn interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        todo!()
    }

    fn confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        todo!()
    }

    fn group_state<
        GroupState: openmls_traits::storage::traits::GroupState<VERSION>,
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        todo!()
    }

    fn message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        MessageSecrets: openmls_traits::storage::traits::MessageSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        todo!()
    }

    fn resumption_psk_store<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        todo!()
    }

    fn own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        todo!()
    }

    fn use_ratchet_tree_extension<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<bool>, Self::Error> {
        todo!()
    }

    fn group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        todo!()
    }

    fn signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<VERSION>,
        SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        todo!()
    }

    fn encryption_key_pair<
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<VERSION>,
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        todo!()
    }

    fn encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        todo!()
    }

    fn key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        todo!()
    }

    fn psk<
        PskBundle: openmls_traits::storage::traits::PskBundle<VERSION>,
        PskId: openmls_traits::storage::traits::PskId<VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        todo!()
    }

    fn delete_group_state<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_message_secrets<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_all_resumption_psk_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_own_leaf_index<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_use_ratchet_tree_extension<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_epoch_secrets<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn clear_proposal_queue<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_signature_key_pair<
        SignaturePublicKeuy: openmls_traits::storage::traits::SignaturePublicKey<VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKeuy,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_psk<PskKey: openmls_traits::storage::traits::PskId<VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn mls_group_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        todo!()
    }

    fn write_mls_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn own_leaf_nodes<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        LeafNode: openmls_traits::storage::traits::LeafNode<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        todo!()
    }

    fn append_own_leaf_node<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        LeafNode: openmls_traits::storage::traits::LeafNode<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn clear_own_leaf_nodes<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn aad<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<u8>, Self::Error> {
        todo!()
    }

    fn write_aad<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
        aad: &[u8],
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn queued_proposals<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        todo!()
    }

    fn remove_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_aad<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_own_leaf_nodes<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_config<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_tree<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_confirmation_tag<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_context<GroupId: openmls_traits::storage::traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

impl PersistentStorage {
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
        let ks_output_path = PersistentStorage::get_file_path(&user_name);

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
        let ks_input_path = PersistentStorage::get_file_path(&user_name);

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
