use super::*;
use std::io::Write;

impl StorageProvider<V_TEST> for MemoryStorageGuard<'_> {
    type Error = MemoryStorageError;

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<V_TEST>,
        HpkeKeyPair: traits::HpkeKeyPair<V_TEST>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write::<V_TEST>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(&public_key).unwrap(),
            serde_json::to_vec(&key_pair).unwrap(),
        )
    }

    fn encryption_epoch_key_pairs<
        EpochKey: traits::EpochKey<V_TEST>,
        HpkeKeyPair: traits::HpkeKeyPair<V_TEST>,
    >(
        &self,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let mut key = vec![];
        write!(
            &mut key,
            "{group_id},{epoch},{leaf_index}",
            group_id = serde_json::to_string(&self.serialized_group_id.bytes).unwrap(),
            epoch = serde_json::to_string(epoch).unwrap(),
        )
        .unwrap();
        self.read_list(ENCRYPTION_KEY_PAIR_LABEL, &key)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<V_TEST>,
        KeyPackage: traits::KeyPackage<V_TEST>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let key = serde_json::to_vec(&hash_ref).unwrap();

        println!("getting key package at {key:?} for version {V_TEST}");
        println!(
            "the whole store when trying to get the key package: {:?}",
            self.storage.values.read().unwrap()
        );
        self.read(KEY_PACKAGE_LABEL, &key)
    }

    fn write_key_package<
        HashReference: traits::HashReference<V_TEST>,
        KeyPackage: traits::KeyPackage<V_TEST>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(&hash_ref).unwrap();
        println!("setting key package at {key:?} for version {V_TEST}");
        let value = serde_json::to_vec(&key_package).unwrap();

        self.write::<V_TEST>(KEY_PACKAGE_LABEL, &key, value)
            .unwrap();

        self.key_package::<HashReference, KeyPackage>(hash_ref)
            .unwrap();

        Ok(())
    }

    fn queue_proposal<
        ProposalRef: traits::ProposalRef<V_TEST>,
        QueuedProposal: traits::QueuedProposal<V_TEST>,
    >(
        &self,

        _proposal_ref: &ProposalRef,
        _proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_tree<TreeSync: traits::TreeSync<V_TEST>>(
        &self,

        _tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_interim_transcript_hash<
        InterimTranscriptHash: traits::InterimTranscriptHash<V_TEST>,
    >(
        &self,

        _interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_context<GroupContext: traits::GroupContext<V_TEST>>(
        &self,

        _group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_confirmation_tag<ConfirmationTag: traits::ConfirmationTag<V_TEST>>(
        &self,

        _confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<V_TEST>,
        SignatureKeyPair: traits::SignatureKeyPair<V_TEST>,
    >(
        &self,
        _public_key: &SignaturePublicKey,
        _signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_encryption_epoch_key_pairs<
        EpochKey: traits::EpochKey<V_TEST>,
        HpkeKeyPair: traits::HpkeKeyPair<V_TEST>,
    >(
        &self,

        _epoch: &EpochKey,
        _leaf_index: u32,
        _key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_psk<PskId: traits::PskId<V_TEST>, PskBundle: traits::PskBundle<V_TEST>>(
        &self,
        _psk_id: &PskId,
        _psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn queued_proposal_refs<ProposalRef: traits::ProposalRef<V_TEST>>(
        &self,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        todo!()
    }

    fn tree<TreeSync: traits::TreeSync<V_TEST>>(&self) -> Result<Option<TreeSync>, Self::Error> {
        todo!()
    }

    fn group_context<GroupContext: traits::GroupContext<V_TEST>>(
        &self,
    ) -> Result<Option<GroupContext>, Self::Error> {
        todo!()
    }

    fn interim_transcript_hash<InterimTranscriptHash: traits::InterimTranscriptHash<V_TEST>>(
        &self,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        todo!()
    }

    fn confirmation_tag<ConfirmationTag: traits::ConfirmationTag<V_TEST>>(
        &self,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        todo!()
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<V_TEST>,
        SignatureKeyPair: traits::SignatureKeyPair<V_TEST>,
    >(
        &self,
        _public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        todo!()
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<V_TEST>,
        EncryptionKey: traits::EncryptionKey<V_TEST>,
    >(
        &self,
        _public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        todo!()
    }

    fn psk<PskBundle: traits::PskBundle<V_TEST>, PskId: traits::PskId<V_TEST>>(
        &self,
        _psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        todo!()
    }

    fn delete_signature_key_pair<SignaturePublicKeuy: traits::SignaturePublicKey<V_TEST>>(
        &self,
        _public_key: &SignaturePublicKeuy,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<V_TEST>>(
        &self,
        _public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_encryption_epoch_key_pairs<EpochKey: traits::EpochKey<V_TEST>>(
        &self,

        _epoch: &EpochKey,
        _leaf_index: u32,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<V_TEST>>(
        &self,
        _hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_psk<PskKey: traits::PskId<V_TEST>>(
        &self,
        _psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn group_state<GroupState: traits::GroupState<V_TEST>>(
        &self,
    ) -> Result<Option<GroupState>, Self::Error> {
        todo!()
    }

    fn write_group_state<GroupState: traits::GroupState<V_TEST>>(
        &self,

        _group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_state(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn message_secrets<MessageSecrets: traits::MessageSecrets<V_TEST>>(
        &self,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        todo!()
    }

    fn write_message_secrets<MessageSecrets: traits::MessageSecrets<V_TEST>>(
        &self,

        _message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_message_secrets(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn resumption_psk_store<ResumptionPskStore: traits::ResumptionPskStore<V_TEST>>(
        &self,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        todo!()
    }

    fn write_resumption_psk_store<ResumptionPskStore: traits::ResumptionPskStore<V_TEST>>(
        &self,

        _resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_all_resumption_psk_secrets(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn own_leaf_index<LeafNodeIndex: traits::LeafNodeIndex<V_TEST>>(
        &self,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        todo!()
    }

    fn write_own_leaf_index<LeafNodeIndex: traits::LeafNodeIndex<V_TEST>>(
        &self,

        _own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_own_leaf_index(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn group_epoch_secrets<GroupEpochSecrets: traits::GroupEpochSecrets<V_TEST>>(
        &self,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        todo!()
    }

    fn write_group_epoch_secrets<GroupEpochSecrets: traits::GroupEpochSecrets<V_TEST>>(
        &self,

        _group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_epoch_secrets(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn clear_proposal_queue<ProposalRef: traits::ProposalRef<V_TEST>>(
        &self,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn mls_group_join_config<MlsGroupJoinConfig: traits::MlsGroupJoinConfig<V_TEST>>(
        &self,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        todo!()
    }

    fn write_mls_join_config<MlsGroupJoinConfig: traits::MlsGroupJoinConfig<V_TEST>>(
        &self,

        _config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn own_leaf_nodes<LeafNode: traits::LeafNode<V_TEST>>(
        &self,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        todo!()
    }

    fn append_own_leaf_node<LeafNode: traits::LeafNode<V_TEST>>(
        &self,

        _leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn queued_proposals<
        ProposalRef: traits::ProposalRef<V_TEST>,
        QueuedProposal: traits::QueuedProposal<V_TEST>,
    >(
        &self,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        todo!()
    }

    fn remove_proposal<ProposalRef: traits::ProposalRef<V_TEST>>(
        &self,

        _proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_own_leaf_nodes(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_config(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_tree(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_confirmation_tag(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_context(&self) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_interim_transcript_hash(&self) -> Result<(), Self::Error> {
        todo!()
    }

    #[cfg(feature = "extensions-draft-08")]
    fn write_application_export_tree<
        ApplicationExportTree: traits::ApplicationExportTree<V_TEST>,
    >(
        &self,

        _application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    #[cfg(feature = "extensions-draft-08")]
    fn application_export_tree<ApplicationExportTree: traits::ApplicationExportTree<V_TEST>>(
        &self,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        todo!()
    }

    #[cfg(feature = "extensions-draft-08")]
    fn delete_application_export_tree<
        ApplicationExportTree: traits::ApplicationExportTree<V_TEST>,
    >(
        &self,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
