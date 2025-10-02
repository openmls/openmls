// SPDX-FileCopyrightText: 2025 Phoenix R&D GmbH <hello@phnx.im>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use tokio_stream::StreamExt;

use std::{future::Future, marker::PhantomData};

use openmls_traits::storage::{
    CURRENT_VERSION, Entity, Key, StorageProvider,
    traits::{
        self, ProposalRef as ProposalRefTrait, SignaturePublicKey as SignaturePublicKeyTrait,
    },
};
use sqlx::{
    Database, Decode, Encode, Row, Sqlite, SqliteExecutor, Type, encode::IsNull,
    error::BoxDynError, query, sqlite::SqliteTypeInfo,
};

use crate::{
    SqliteStorageProvider, codec::Codec, encryption_key_pairs::StorableEncryptionKeyPairRef,
};

use super::{
    EntityRefWrapper, EntitySliceWrapper, EntityVecWrapper, EntityWrapper, KeyRefWrapper,
    StorableGroupIdRef,
    encryption_key_pairs::{StorableEncryptionKeyPair, StorableEncryptionPublicKeyRef},
    epoch_key_pairs::{StorableEpochKeyPairs, StorableEpochKeyPairsRef},
    group_data::{GroupDataType, StorableGroupData, StorableGroupDataRef},
    key_packages::{StorableHashRef, StorableKeyPackage, StorableKeyPackageRef},
    own_leaf_nodes::{StorableLeafNode, StorableLeafNodeRef},
    proposals::{StorableProposal, StorableProposalRef},
    psks::{StorablePskBundle, StorablePskBundleRef, StorablePskIdRef},
    signature_key_pairs::{
        StorableSignatureKeyPairs, StorableSignatureKeyPairsRef, StorableSignaturePublicKeyRef,
    },
};

impl<C: Codec> StorageProvider<CURRENT_VERSION> for SqliteStorageProvider<'_, C> {
    type Error = sqlx::Error;

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(config);
        let mut connection = self.connection.borrow_mut();
        let task =
            storable.store::<_, C>(&mut **connection, group_id, GroupDataType::JoinGroupConfig);
        block_async_in_place(task)
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let storable = StorableLeafNodeRef(leaf_node);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, group_id);
        block_async_in_place(task)
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        let storable = StorableProposalRef(proposal_ref, proposal);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, group_id);
        block_async_in_place(task)
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(tree);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, group_id, GroupDataType::Tree);
        block_async_in_place(task)
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(interim_transcript_hash);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::InterimTranscriptHash,
        );
        block_async_in_place(task)
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(group_context);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, group_id, GroupDataType::Context);
        block_async_in_place(task)
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(confirmation_tag);
        let mut connection = self.connection.borrow_mut();
        let task =
            storable.store::<_, C>(&mut **connection, group_id, GroupDataType::ConfirmationTag);
        block_async_in_place(task)
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(group_state);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, group_id, GroupDataType::GroupState);
        block_async_in_place(task)
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(message_secrets);
        let mut connection = self.connection.borrow_mut();
        let task =
            storable.store::<_, C>(&mut **connection, group_id, GroupDataType::MessageSecrets);
        block_async_in_place(task)
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(resumption_psk_store);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::ResumptionPskStore,
        );
        block_async_in_place(task)
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(own_leaf_index);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, group_id, GroupDataType::OwnLeafIndex);
        block_async_in_place(task)
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        let storable = StorableGroupDataRef(group_epoch_secrets);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::GroupEpochSecrets,
        );
        block_async_in_place(task)
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        let storable = StorableSignatureKeyPairsRef(signature_key_pair);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, public_key);
        block_async_in_place(task)
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        let storable = StorableEncryptionKeyPairRef(key_pair);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, public_key);
        block_async_in_place(task)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let storable = StorableEpochKeyPairsRef(key_pairs);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, _, C>(&mut **connection, group_id, epoch, leaf_index);
        block_async_in_place(task)
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        let storable = StorableKeyPackageRef(key_package);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, hash_ref);
        block_async_in_place(task)
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        let storable = StorablePskBundleRef(psk);
        let mut connection = self.connection.borrow_mut();
        let task = storable.store::<_, C>(&mut **connection, psk_id);
        block_async_in_place(task)
    }

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableGroupData::load::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::JoinGroupConfig,
        );
        block_async_in_place(task)
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableLeafNode::load::<_, C>(&mut **connection, group_id);
        block_async_in_place(task)
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task =
            StorableProposal::<u8, ProposalRef>::load_refs::<_, C>(&mut **connection, group_id);
        block_async_in_place(task)
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableProposal::load::<_, C>(&mut **connection, group_id);
        block_async_in_place(task)
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task =
            StorableGroupData::load::<_, C>(&mut **connection, group_id, GroupDataType::Tree);
        block_async_in_place(task)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task =
            StorableGroupData::load::<_, C>(&mut **connection, group_id, GroupDataType::Context);
        block_async_in_place(task)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableGroupData::load::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::InterimTranscriptHash,
        );
        block_async_in_place(task)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableGroupData::load::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::ConfirmationTag,
        );
        block_async_in_place(task)
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task =
            StorableGroupData::load::<_, C>(&mut **connection, group_id, GroupDataType::GroupState);
        block_async_in_place(task)
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableGroupData::load::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::MessageSecrets,
        );
        block_async_in_place(task)
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableGroupData::load::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::ResumptionPskStore,
        );
        block_async_in_place(task)
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableGroupData::load::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::OwnLeafIndex,
        );
        block_async_in_place(task)
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableGroupData::load::<_, C>(
            &mut **connection,
            group_id,
            GroupDataType::GroupEpochSecrets,
        );
        block_async_in_place(task)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableSignatureKeyPairs::load::<_, C>(&mut **connection, public_key);
        block_async_in_place(task)
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableEncryptionKeyPair::load::<_, C>(&mut **connection, public_key);
        block_async_in_place(task)
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task =
            StorableEpochKeyPairs::load::<_, _, C>(&mut **connection, group_id, epoch, leaf_index);
        block_async_in_place(task)
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorableKeyPackage::load::<_, C>(&mut **connection, hash_ref);
        block_async_in_place(task)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let task = StorablePskBundle::load::<_, C>(&mut **connection, psk_id);
        block_async_in_place(task)
    }

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let mut connection = self.connection.borrow_mut();
        let storable = self.wrap_storable_group_id_ref(group_id);
        let task = storable.delete_proposal(&mut **connection, proposal_ref);
        block_async_in_place(task)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_leaf_nodes(&mut **connection);
        block_async_in_place(task)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::JoinGroupConfig);
        block_async_in_place(task)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::Tree);
        block_async_in_place(task)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::ConfirmationTag);
        block_async_in_place(task)
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::GroupState);
        block_async_in_place(task)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::Context);
        block_async_in_place(task)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task =
            storable.delete_group_data(&mut **connection, GroupDataType::InterimTranscriptHash);
        block_async_in_place(task)
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::MessageSecrets);
        block_async_in_place(task)
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::ResumptionPskStore);
        block_async_in_place(task)
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::OwnLeafIndex);
        block_async_in_place(task)
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_group_data(&mut **connection, GroupDataType::GroupEpochSecrets);
        block_async_in_place(task)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_all_proposals(&mut **connection);
        block_async_in_place(task)
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        let storable = StorableSignaturePublicKeyRef(public_key);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete::<C>(&mut **connection);
        block_async_in_place(task)
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        let storable = StorableEncryptionPublicKeyRef(public_key);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete::<C>(&mut **connection);
        block_async_in_place(task)
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let storable = self.wrap_storable_group_id_ref(group_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_epoch_key_pair(&mut **connection, epoch, leaf_index);
        block_async_in_place(task)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        let storable = StorableHashRef(hash_ref);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete_key_package::<C>(&mut **connection);
        block_async_in_place(task)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        let storable = StorablePskIdRef(psk_id);
        let mut connection = self.connection.borrow_mut();
        let task = storable.delete::<C>(&mut **connection);
        block_async_in_place(task)
    }
}

impl<T: Key<CURRENT_VERSION>, C: Codec> Type<Sqlite> for KeyRefWrapper<'_, T, C> {
    fn type_info() -> SqliteTypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }
}

impl<'q, T: Key<CURRENT_VERSION>, C: Codec> Encode<'q, Sqlite> for KeyRefWrapper<'_, T, C> {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as sqlx::Database>::ArgumentBuffer<'q>,
    ) -> Result<sqlx::encode::IsNull, sqlx::error::BoxDynError> {
        let key_bytes = C::to_vec(self.0)?;
        Encode::<Sqlite>::encode(key_bytes, buf)
    }
}

impl<T: Entity<CURRENT_VERSION>, C: Codec> Type<Sqlite> for EntityRefWrapper<'_, T, C> {
    fn type_info() -> <Sqlite as Database>::TypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }
}

impl<T: Entity<CURRENT_VERSION>, C: Codec> Encode<'_, Sqlite> for EntityRefWrapper<'_, T, C> {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as Database>::ArgumentBuffer<'_>,
    ) -> Result<IsNull, BoxDynError> {
        let entity_bytes = C::to_vec(self.0)?;
        Encode::<Sqlite>::encode(entity_bytes, buf)
    }
}

impl<GroupData: Entity<CURRENT_VERSION>> StorableGroupDataRef<'_, GroupData> {
    pub(super) async fn store<GroupId: Key<CURRENT_VERSION>, C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
        data_type: GroupDataType,
    ) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(group_id, PhantomData);
        let group_data = EntityRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "INSERT OR REPLACE INTO openmls_group_data (group_id, data_type, group_data) VALUES (?, ?, ?)",
            group_id,
            data_type,
            group_data,
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<SignatureKeyPairs: Entity<CURRENT_VERSION>>
    StorableSignatureKeyPairsRef<'_, SignatureKeyPairs>
{
    async fn store<SignaturePublicKey: Key<CURRENT_VERSION>, C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
        public_key: &SignaturePublicKey,
    ) -> sqlx::Result<()> {
        let public_key = KeyRefWrapper::<_, C>(public_key, PhantomData);
        let signature_key = EntityRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "INSERT INTO openmls_signature_key (public_key, signature_key) VALUES (?1, ?2)",
            public_key,
            signature_key
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<LeafNode: Entity<CURRENT_VERSION>> StorableLeafNodeRef<'_, LeafNode> {
    async fn store<GroupId: Key<CURRENT_VERSION>, C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
    ) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(group_id, PhantomData);
        let entity = EntityRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "INSERT INTO openmls_own_leaf_node (group_id, leaf_node) VALUES (?1, ?2)",
            group_id,
            entity,
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<T: Entity<CURRENT_VERSION>, C: Codec> Type<Sqlite> for EntitySliceWrapper<'_, T, C> {
    fn type_info() -> <Sqlite as Database>::TypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }
}

impl<T: Entity<CURRENT_VERSION>, C: Codec> Encode<'_, Sqlite> for EntitySliceWrapper<'_, T, C> {
    fn encode_by_ref(
        &self,
        buf: &mut <Sqlite as Database>::ArgumentBuffer<'_>,
    ) -> Result<IsNull, BoxDynError> {
        let entity_bytes = C::to_vec(self.0)?;
        Encode::<Sqlite>::encode(entity_bytes, buf)
    }
}

impl<KeyPackage: Entity<CURRENT_VERSION>> StorableKeyPackageRef<'_, KeyPackage> {
    async fn store<KeyPackageRef: Key<CURRENT_VERSION>, C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
        key_package_ref: &KeyPackageRef,
    ) -> sqlx::Result<()> {
        let key_package_ref = KeyRefWrapper::<_, C>(key_package_ref, PhantomData);
        let key_package = EntityRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "INSERT INTO openmls_key_package (key_package_ref, key_package) VALUES (?1, ?2)",
            key_package_ref,
            key_package,
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<EpochKeyPairs: Entity<CURRENT_VERSION>> StorableEpochKeyPairsRef<'_, EpochKeyPairs> {
    async fn store<GroupId: Key<CURRENT_VERSION>, EpochKey: Key<CURRENT_VERSION>, C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
        epoch_id: &EpochKey,
        leaf_index: u32,
    ) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(group_id, PhantomData);
        let epoch_id = KeyRefWrapper::<_, C>(epoch_id, PhantomData);
        let entity = EntitySliceWrapper::<_, C>(self.0, PhantomData);
        query!(
            "INSERT INTO openmls_epoch_key_pairs (group_id, epoch_id, leaf_index, key_pairs)
            VALUES (?1, ?2, ?3, ?4)",
            group_id,
            epoch_id,
            leaf_index,
            entity,
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<PskBundle: Entity<CURRENT_VERSION>> StorablePskBundleRef<'_, PskBundle> {
    async fn store<PskId: Key<CURRENT_VERSION>, C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
        psk_id: &PskId,
    ) -> sqlx::Result<()> {
        let psk_id = KeyRefWrapper::<_, C>(psk_id, PhantomData);
        let psk_bundle = EntityRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "INSERT INTO openmls_psk (psk_id, psk_bundle) VALUES (?1, ?2)",
            psk_id,
            psk_bundle,
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<T: Entity<CURRENT_VERSION>, C: Codec> Type<Sqlite> for EntityWrapper<T, C> {
    fn type_info() -> <Sqlite as Database>::TypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }
}

impl<T: Entity<CURRENT_VERSION>, C: Codec> Decode<'_, Sqlite> for EntityWrapper<T, C> {
    fn decode(value: <Sqlite as Database>::ValueRef<'_>) -> Result<Self, BoxDynError> {
        let bytes: &[u8] = Decode::<Sqlite>::decode(value)?;
        let entity = C::from_slice(bytes)?;
        Ok(Self(entity, PhantomData))
    }
}

impl<GroupData: Entity<CURRENT_VERSION>> StorableGroupData<GroupData> {
    async fn load<GroupId: Key<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
        data_type: GroupDataType,
    ) -> sqlx::Result<Option<GroupData>> {
        sqlx::query(
            "SELECT group_data FROM openmls_group_data WHERE group_id = ? AND data_type = ?",
        )
        .bind(KeyRefWrapper::<_, C>(group_id, PhantomData))
        .bind(data_type)
        .fetch_optional(executor)
        .await?
        .map(|row| {
            let EntityWrapper(group_data, PhantomData::<C>) = row.try_get(0)?;
            Ok(group_data)
        })
        .transpose()
    }
}

impl<Proposal: Entity<CURRENT_VERSION>, ProposalRef: Entity<CURRENT_VERSION>>
    StorableProposalRef<'_, Proposal, ProposalRef>
{
    async fn store<GroupId: Key<CURRENT_VERSION>, C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
    ) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(group_id, PhantomData);
        let proposal_ref = EntityRefWrapper::<_, C>(self.0, PhantomData);
        let proposal = EntityRefWrapper::<_, C>(self.1, PhantomData);
        query!(
            "INSERT INTO openmls_proposal (group_id, proposal_ref, proposal) VALUES (?1, ?2, ?3)",
            group_id,
            proposal_ref,
            proposal
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<LeafNode: Entity<CURRENT_VERSION>> StorableLeafNode<LeafNode> {
    async fn load<GroupId: Key<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
    ) -> sqlx::Result<Vec<LeafNode>> {
        sqlx::query("SELECT leaf_node FROM openmls_leaf_node WHERE group_id = ?")
            .bind(KeyRefWrapper::<_, C>(group_id, PhantomData))
            .fetch(executor)
            .map(|row| {
                let EntityWrapper(leaf_node, PhantomData::<C>) = row?.try_get(0)?;
                Ok(leaf_node)
            })
            .collect()
            .await
    }
}

impl<Proposal: Entity<CURRENT_VERSION>, ProposalRef: Entity<CURRENT_VERSION>>
    StorableProposal<Proposal, ProposalRef>
{
    async fn load<GroupId: Key<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
    ) -> sqlx::Result<Vec<(ProposalRef, Proposal)>> {
        sqlx::query("SELECT proposal_ref, proposal FROM openmls_proposal WHERE group_id = ?1")
            .bind(KeyRefWrapper::<_, C>(group_id, PhantomData))
            .fetch(executor)
            .map(|row| {
                let row = row?;
                let EntityWrapper(proposal_ref, PhantomData::<C>) = row.try_get(0)?;
                let EntityWrapper(proposal, PhantomData::<C>) = row.try_get(1)?;
                Ok((proposal_ref, proposal))
            })
            .collect()
            .await
    }

    async fn load_refs<GroupId: Key<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
    ) -> sqlx::Result<Vec<ProposalRef>> {
        sqlx::query("SELECT proposal_ref FROM openmlsproposal WHERE group_id = ?1")
            .bind(KeyRefWrapper::<_, C>(group_id, PhantomData))
            .fetch(executor)
            .map(|row| {
                let EntityWrapper(proposal_ref, PhantomData::<C>) = row?.try_get(0)?;
                Ok(proposal_ref)
            })
            .collect()
            .await
    }
}

impl<SignatureKeyPairs: Entity<CURRENT_VERSION>> StorableSignatureKeyPairs<SignatureKeyPairs> {
    async fn load<SignaturePublicKey: SignaturePublicKeyTrait<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        public_key: &SignaturePublicKey,
    ) -> sqlx::Result<Option<SignatureKeyPairs>> {
        sqlx::query("SELECT signature_key FROM openmls_signature_key WHERE public_key = ?1")
            .bind(KeyRefWrapper::<_, C>(public_key, PhantomData))
            .fetch_optional(executor)
            .await?
            .map(|row| {
                let EntityWrapper(signature_key, PhantomData::<C>) = row.try_get(0)?;
                Ok(signature_key)
            })
            .transpose()
    }
}

impl<EncryptionKeyPair: Entity<CURRENT_VERSION>> StorableEncryptionKeyPair<EncryptionKeyPair> {
    async fn load<EncryptionKey: Key<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        public_key: &EncryptionKey,
    ) -> sqlx::Result<Option<EncryptionKeyPair>> {
        sqlx::query("SELECT key_pair FROM openmls_encryption_key WHERE public_key = ?1")
            .bind(KeyRefWrapper::<_, C>(public_key, PhantomData))
            .fetch_optional(executor)
            .await?
            .map(|row| {
                let EntityWrapper(encryption_key_pair, PhantomData::<C>) = row.try_get(0)?;
                Ok(encryption_key_pair)
            })
            .transpose()
    }
}

impl<EncryptionKeyPair: Entity<CURRENT_VERSION>>
    StorableEncryptionKeyPairRef<'_, EncryptionKeyPair>
{
    async fn store<EncryptionKey: Key<CURRENT_VERSION>, C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
        public_key: &EncryptionKey,
    ) -> sqlx::Result<()> {
        let public_key = KeyRefWrapper::<_, C>(public_key, PhantomData);
        let key_pair = EntityRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "INSERT INTO openmls_encryption_key (public_key, key_pair) VALUES (?1, ?2)",
            public_key,
            key_pair
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<EpochKeyPairs: Entity<CURRENT_VERSION>> StorableEpochKeyPairs<EpochKeyPairs> {
    async fn load<GroupId: Key<CURRENT_VERSION>, EpochKey: Key<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        group_id: &GroupId,
        epoch_id: &EpochKey,
        leaf_index: u32,
    ) -> sqlx::Result<Vec<EpochKeyPairs>> {
        let group_id = KeyRefWrapper::<_, C>(group_id, PhantomData);
        let epoch_id = KeyRefWrapper::<_, C>(epoch_id, PhantomData);
        sqlx::query(
            "SELECT key_pairs FROM openmls_epoch_key_pairs
            WHERE group_id = ?1 AND epoch_id = ?2 AND leaf_index = ?3",
        )
        .bind(group_id)
        .bind(epoch_id)
        .bind(leaf_index)
        .fetch_optional(executor)
        .await?
        .map(|row| {
            let EntityVecWrapper(key_pairs, PhantomData::<C>) = row.try_get(0)?;
            Ok(key_pairs)
        })
        .transpose()
        .map(|res| res.unwrap_or_default())
    }
}

impl<T: Entity<CURRENT_VERSION>, C: Codec> Type<Sqlite> for EntityVecWrapper<T, C> {
    fn type_info() -> <Sqlite as Database>::TypeInfo {
        <Vec<u8> as Type<Sqlite>>::type_info()
    }
}

impl<T: Entity<CURRENT_VERSION>, C: Codec> Decode<'_, Sqlite> for EntityVecWrapper<T, C> {
    fn decode(value: <Sqlite as Database>::ValueRef<'_>) -> Result<Self, BoxDynError> {
        let bytes: &[u8] = Decode::<Sqlite>::decode(value)?;
        let entities = C::from_slice(bytes)?;
        Ok(Self(entities, PhantomData))
    }
}

impl<KeyPackage: Entity<CURRENT_VERSION>> StorableKeyPackage<KeyPackage> {
    async fn load<KeyPackageRef: Key<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        key_package_ref: &KeyPackageRef,
    ) -> sqlx::Result<Option<KeyPackage>> {
        sqlx::query("SELECT key_package FROM openmls_key_package WHERE key_package_ref = ?1")
            .bind(KeyRefWrapper::<_, C>(key_package_ref, PhantomData))
            .fetch_optional(executor)
            .await?
            .map(|row| {
                let EntityWrapper(key_package, PhantomData::<C>) = row.try_get(0)?;
                Ok(key_package)
            })
            .transpose()
    }
}

impl<PskBundle: Entity<CURRENT_VERSION>> StorablePskBundle<PskBundle> {
    async fn load<PskId: Key<CURRENT_VERSION>, C: Codec>(
        executor: impl SqliteExecutor<'_>,
        psk_id: &PskId,
    ) -> sqlx::Result<Option<PskBundle>> {
        sqlx::query("SELECT psk_bundle FROM openmls_psk WHERE psk_id = ?1")
            .bind(KeyRefWrapper::<_, C>(psk_id, PhantomData))
            .fetch_optional(executor)
            .await?
            .map(|row| {
                let EntityWrapper(psk, PhantomData::<C>) = row.try_get(0)?;
                Ok(psk)
            })
            .transpose()
    }
}

impl<GroupId: Key<CURRENT_VERSION>, C: Codec> StorableGroupIdRef<'_, GroupId, C> {
    async fn delete_all_proposals(&self, executor: impl SqliteExecutor<'_>) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
        query!("DELETE FROM openmls_proposal WHERE group_id = ?1", group_id)
            .execute(executor)
            .await?;
        Ok(())
    }

    async fn delete_proposal<ProposalRef: ProposalRefTrait<CURRENT_VERSION>>(
        &self,
        executor: impl SqliteExecutor<'_>,
        proposal_ref: &ProposalRef,
    ) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
        let proposal_ref = KeyRefWrapper::<_, C>(proposal_ref, PhantomData);
        query!(
            "DELETE FROM openmls_proposal WHERE group_id = ?1 AND proposal_ref = ?2",
            group_id,
            proposal_ref,
        )
        .execute(executor)
        .await?;
        Ok(())
    }

    async fn delete_leaf_nodes(&self, executor: impl SqliteExecutor<'_>) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "DELETE FROM openmls_own_leaf_node WHERE group_id = ?1",
            group_id
        )
        .execute(executor)
        .await?;
        Ok(())
    }

    async fn delete_group_data(
        &self,
        executor: impl SqliteExecutor<'_>,
        data_type: GroupDataType,
    ) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "DELETE FROM openmls_group_data WHERE group_id = ? AND data_type = ?",
            group_id,
            data_type
        )
        .execute(executor)
        .await?;
        Ok(())
    }

    async fn delete_epoch_key_pair<EpochKey: Key<CURRENT_VERSION>>(
        &self,
        executor: impl SqliteExecutor<'_>,
        epoch_key: &EpochKey,
        leaf_index: u32,
    ) -> sqlx::Result<()> {
        let group_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
        let epoch_key = KeyRefWrapper::<_, C>(epoch_key, PhantomData);
        query!(
            "DELETE FROM openmls_epoch_key_pairs WHERE group_id = ? AND epoch_id = ? AND leaf_index = ?",
            group_id,
            epoch_key,
            leaf_index,
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<SignaturePublicKey: Key<CURRENT_VERSION>>
    StorableSignaturePublicKeyRef<'_, SignaturePublicKey>
{
    async fn delete<C: Codec>(&self, executor: impl SqliteExecutor<'_>) -> sqlx::Result<()> {
        let public_key = KeyRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "DELETE FROM openmls_signature_key WHERE public_key = ?1",
            public_key
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<EncryptionPublicKey: Key<CURRENT_VERSION>>
    StorableEncryptionPublicKeyRef<'_, EncryptionPublicKey>
{
    async fn delete<C: Codec>(&self, executor: impl SqliteExecutor<'_>) -> sqlx::Result<()> {
        let public_key = KeyRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "DELETE FROM openmls_encryption_key WHERE public_key = ?1",
            public_key
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<KeyPackageRef: Key<CURRENT_VERSION>> StorableHashRef<'_, KeyPackageRef> {
    async fn delete_key_package<C: Codec>(
        &self,
        executor: impl SqliteExecutor<'_>,
    ) -> sqlx::Result<()> {
        let hash_ref = KeyRefWrapper::<_, C>(self.0, PhantomData);
        query!(
            "DELETE FROM openmls_key_package WHERE key_package_ref = ?1",
            hash_ref,
        )
        .execute(executor)
        .await?;
        Ok(())
    }
}

impl<PskId: Key<CURRENT_VERSION>> StorablePskIdRef<'_, PskId> {
    async fn delete<C: Codec>(&self, executor: impl SqliteExecutor<'_>) -> sqlx::Result<()> {
        let psks_id = KeyRefWrapper::<_, C>(self.0, PhantomData);
        query!("DELETE FROM openmls_psk WHERE psk_id = ?1", psks_id)
            .execute(executor)
            .await?;
        Ok(())
    }
}

/// Runs and waits for the given future to complete in a synchronous context.
///
/// Note that even though this function is called in a synchronous context, at some point down the
/// stack it must be called in a multi-threaded asynchronous context. In particular, tests must be
/// asynchronous and of flavor `multi_thread`.
pub(super) fn block_async_in_place<F>(task: F) -> F::Output
where
    F: Future,
{
    tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(task))
}
