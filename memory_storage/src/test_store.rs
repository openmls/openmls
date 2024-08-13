use super::*;
use std::io::Write;

impl StorageProvider<V_TEST> for MemoryStorage {
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
        GroupId: traits::GroupId<V_TEST>,
        EpochKey: traits::EpochKey<V_TEST>,
        HpkeKeyPair: traits::HpkeKeyPair<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let mut key = vec![];
        write!(
            &mut key,
            "{group_id},{epoch},{leaf_index}",
            group_id = serde_json::to_string(group_id).unwrap(),
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
            self.values.read().unwrap()
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
        GroupId: traits::GroupId<V_TEST>,
        ProposalRef: traits::ProposalRef<V_TEST>,
        QueuedProposal: traits::QueuedProposal<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _proposal_ref: &ProposalRef,
        _proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_tree<GroupId: traits::GroupId<V_TEST>, TreeSync: traits::TreeSync<V_TEST>>(
        &self,
        _group_id: &GroupId,
        _tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<V_TEST>,
        InterimTranscriptHash: traits::InterimTranscriptHash<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_context<
        GroupId: traits::GroupId<V_TEST>,
        GroupContext: traits::GroupContext<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<V_TEST>,
        ConfirmationTag: traits::ConfirmationTag<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
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
        GroupId: traits::GroupId<V_TEST>,
        EpochKey: traits::EpochKey<V_TEST>,
        HpkeKeyPair: traits::HpkeKeyPair<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
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

    fn queued_proposal_refs<
        GroupId: traits::GroupId<V_TEST>,
        ProposalRef: traits::ProposalRef<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        todo!()
    }

    fn tree<GroupId: traits::GroupId<V_TEST>, TreeSync: traits::TreeSync<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        todo!()
    }

    fn group_context<
        GroupId: traits::GroupId<V_TEST>,
        GroupContext: traits::GroupContext<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        todo!()
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<V_TEST>,
        InterimTranscriptHash: traits::InterimTranscriptHash<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        todo!()
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<V_TEST>,
        ConfirmationTag: traits::ConfirmationTag<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
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

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V_TEST>,
        EpochKey: traits::EpochKey<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
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

    fn group_state<GroupState: traits::GroupState<V_TEST>, GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        todo!()
    }

    fn write_group_state<
        GroupState: traits::GroupState<V_TEST>,
        GroupId: traits::GroupId<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_state<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn message_secrets<
        GroupId: traits::GroupId<V_TEST>,
        MessageSecrets: traits::MessageSecrets<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        todo!()
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<V_TEST>,
        MessageSecrets: traits::MessageSecrets<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_message_secrets<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<V_TEST>,
        ResumptionPskStore: traits::ResumptionPskStore<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        todo!()
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<V_TEST>,
        ResumptionPskStore: traits::ResumptionPskStore<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<V_TEST>,
        LeafNodeIndex: traits::LeafNodeIndex<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        todo!()
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<V_TEST>,
        LeafNodeIndex: traits::LeafNodeIndex<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<V_TEST>,
        GroupEpochSecrets: traits::GroupEpochSecrets<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        todo!()
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<V_TEST>,
        GroupEpochSecrets: traits::GroupEpochSecrets<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<V_TEST>,
        ProposalRef: traits::ProposalRef<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<V_TEST>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        todo!()
    }

    fn write_mls_join_config<
        GroupId: traits::GroupId<V_TEST>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn own_leaf_nodes<GroupId: traits::GroupId<V_TEST>, LeafNode: traits::LeafNode<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        todo!()
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<V_TEST>,
        LeafNode: traits::LeafNode<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn queued_proposals<
        GroupId: traits::GroupId<V_TEST>,
        ProposalRef: traits::ProposalRef<V_TEST>,
        QueuedProposal: traits::QueuedProposal<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        todo!()
    }

    fn remove_proposal<
        GroupId: traits::GroupId<V_TEST>,
        ProposalRef: traits::ProposalRef<V_TEST>,
    >(
        &self,
        _group_id: &GroupId,
        _proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_config<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_tree<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_context<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<V_TEST>>(
        &self,
        _group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}
