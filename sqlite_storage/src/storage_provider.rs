use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use openmls_traits::storage::{Entity, Key, StorageProvider};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::{
    codec::Codec,
    encryption_key_pairs::{
        StorableEncryptionKeyPair, StorableEncryptionKeyPairRef, StorableEncryptionPublicKeyRef,
    },
    epoch_key_pairs::{StorableEpochKeyPairs, StorableEpochKeyPairsRef},
    group_data::{GroupDataType, StorableGroupData, StorableGroupDataRef},
    key_packages::{StorableHashRef, StorableKeyPackage, StorableKeyPackageRef},
    own_leaf_nodes::{StorableLeafNode, StorableLeafNodeRef},
    proposals::{StorableProposal, StorableProposalRef},
    psks::{StorablePskBundle, StorablePskBundleRef, StorablePskIdRef},
    signature_key_pairs::{
        StorableSignatureKeyPairs, StorableSignatureKeyPairsRef, StorableSignaturePublicKeyRef,
    },
    STORAGE_PROVIDER_VERSION,
};

refinery::embed_migrations!("migrations");

/// Storage provider for OpenMLS using Sqlite through the `rusqlite` crate.
/// Implements the [`StorageProvider`] trait. The codec used by the storage
/// provider is set by the generic parameter `C`.
pub struct SqliteStorageProvider<C: Codec, ConnectionRef: Borrow<Connection>> {
    connection: ConnectionRef,
    _codec: PhantomData<C>,
}

impl<C: Codec, ConnectionRef: Borrow<Connection>> SqliteStorageProvider<C, ConnectionRef> {
    /// Create a new instance of the [`SqliteStorageProvider`].
    pub fn new(connection: ConnectionRef) -> Self {
        Self {
            connection,
            _codec: PhantomData,
        }
    }
}

impl<C: Codec, ConnectionRef: BorrowMut<Connection>> SqliteStorageProvider<C, ConnectionRef> {
    /// Initialize the database with the necessary tables.
    ///
    /// This method is deprecated and replaced by `run_migrations`, which
    /// specifies a unique name for the refinery migration table.
    #[deprecated(since = "0.2.0", note = "use `run_migrations()` instead")]
    pub fn initialize(&mut self) -> Result<(), refinery::Error> {
        migrations::runner().run(self.connection.borrow_mut())?;
        Ok(())
    }

    /// Initialize the database with the necessary tables.
    pub fn run_migrations(&mut self) -> Result<(), refinery::Error> {
        let mut runner = migrations::runner();
        runner.set_migration_table_name("openmls_sqlite_storage_migrations");

        runner.run(self.connection.borrow_mut())?;
        Ok(())
    }
}

pub(super) struct StorableGroupIdRef<'a, GroupId: Key<STORAGE_PROVIDER_VERSION>>(pub &'a GroupId);

impl<C: Codec, ConnectionRef: Borrow<Connection>> StorageProvider<STORAGE_PROVIDER_VERSION>
    for SqliteStorageProvider<C, ConnectionRef>
{
    type Error = rusqlite::Error;

    fn write_mls_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(config).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::JoinGroupConfig,
        )
    }

    fn append_own_leaf_node<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNode: openmls_traits::storage::traits::LeafNode<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        StorableLeafNodeRef(leaf_node).store::<C, _>(self.connection.borrow(), group_id)
    }

    fn queue_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        StorableProposalRef(proposal_ref, proposal)
            .store::<C, _>(self.connection.borrow(), group_id)
    }

    fn write_tree<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(tree).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::Tree,
        )
    }

    fn write_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(interim_transcript_hash).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::InterimTranscriptHash,
        )
    }

    fn write_context<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_context).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::Context,
        )
    }

    fn write_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(confirmation_tag).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::ConfirmationTag,
        )
    }

    fn write_group_state<
        GroupState: openmls_traits::storage::traits::GroupState<STORAGE_PROVIDER_VERSION>,
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_state).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::GroupState,
        )
    }

    fn write_message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MessageSecrets: openmls_traits::storage::traits::MessageSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(message_secrets).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::MessageSecrets,
        )?;
        Ok(())
    }

    fn write_resumption_psk_store<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(resumption_psk_store).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::ResumptionPskStore,
        )
    }

    fn write_own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(own_leaf_index).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::OwnLeafIndex,
        )?;
        Ok(())
    }

    fn write_group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        StorableGroupDataRef(group_epoch_secrets).store::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::GroupEpochSecrets,
        )?;
        Ok(())
    }

    fn write_signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
        SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        StorableSignatureKeyPairsRef(signature_key_pair)
            .store::<C, _>(self.connection.borrow(), public_key)
    }

    fn write_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        StorableEncryptionKeyPairRef(key_pair).store::<C, _>(self.connection.borrow(), public_key)
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        StorableEpochKeyPairsRef(key_pairs).store::<C, _, _>(
            self.connection.borrow(),
            group_id,
            epoch,
            leaf_index,
        )
    }

    fn write_key_package<
        HashReference: openmls_traits::storage::traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        StorableKeyPackageRef(key_package).store::<C, _>(self.connection.borrow(), hash_ref)
    }

    fn write_psk<
        PskId: openmls_traits::storage::traits::PskId<STORAGE_PROVIDER_VERSION>,
        PskBundle: openmls_traits::storage::traits::PskBundle<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        StorablePskBundleRef(psk).store::<C, _>(self.connection.borrow(), psk_id)
    }

    fn mls_group_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        StorableGroupData::load::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::JoinGroupConfig,
        )
    }

    fn own_leaf_nodes<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNode: openmls_traits::storage::traits::LeafNode<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        StorableLeafNode::load::<C, _>(self.connection.borrow(), group_id)
    }

    fn queued_proposal_refs<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        StorableProposal::<u8, ProposalRef>::load_refs::<C, _>(self.connection.borrow(), group_id)
    }

    fn queued_proposals<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        StorableProposal::load::<C, _>(self.connection.borrow(), group_id)
    }

    fn tree<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        StorableGroupData::load::<C, _>(self.connection.borrow(), group_id, GroupDataType::Tree)
    }

    fn group_context<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        StorableGroupData::load::<C, _>(self.connection.borrow(), group_id, GroupDataType::Context)
    }

    fn interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        StorableGroupData::load::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::InterimTranscriptHash,
        )
    }

    fn confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        StorableGroupData::load::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::ConfirmationTag,
        )
    }

    fn group_state<
        GroupState: openmls_traits::storage::traits::GroupState<STORAGE_PROVIDER_VERSION>,
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        StorableGroupData::load::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::GroupState,
        )
    }

    fn message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MessageSecrets: openmls_traits::storage::traits::MessageSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        StorableGroupData::load::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::MessageSecrets,
        )
    }

    fn resumption_psk_store<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        StorableGroupData::load::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::ResumptionPskStore,
        )
    }

    fn own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        StorableGroupData::load::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::OwnLeafIndex,
        )
    }

    fn group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        StorableGroupData::load::<C, _>(
            self.connection.borrow(),
            group_id,
            GroupDataType::GroupEpochSecrets,
        )
    }

    fn signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
        SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        StorableSignatureKeyPairs::load::<C, _>(self.connection.borrow(), public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        StorableEncryptionKeyPair::load::<C, _>(self.connection.borrow(), public_key)
    }

    fn encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        StorableEpochKeyPairs::load::<C, _, _>(
            self.connection.borrow(),
            group_id,
            epoch,
            leaf_index,
        )
    }

    fn key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        StorableKeyPackage::load::<C, _>(self.connection.borrow(), hash_ref)
    }

    fn psk<
        PskBundle: openmls_traits::storage::traits::PskBundle<STORAGE_PROVIDER_VERSION>,
        PskId: openmls_traits::storage::traits::PskId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        StorablePskBundle::load::<C, _>(self.connection.borrow(), psk_id)
    }

    fn remove_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_proposal::<C, _>(self.connection.borrow(), proposal_ref)
    }

    fn delete_own_leaf_nodes<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_leaf_nodes::<C>(self.connection.borrow())
    }

    fn delete_group_config<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::JoinGroupConfig)
    }

    fn delete_tree<GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::Tree)
    }

    fn delete_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::ConfirmationTag)
    }

    fn delete_group_state<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::GroupState)
    }

    fn delete_context<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::Context)
    }

    fn delete_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            self.connection.borrow(),
            GroupDataType::InterimTranscriptHash,
        )
    }

    fn delete_message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::MessageSecrets)
    }

    fn delete_all_resumption_psk_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::ResumptionPskStore)
    }

    fn delete_own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::OwnLeafIndex)
    }

    fn delete_group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id)
            .delete_group_data::<C>(self.connection.borrow(), GroupDataType::GroupEpochSecrets)
    }

    fn clear_proposal_queue<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_all_proposals::<C>(self.connection.borrow())?;
        Ok(())
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        StorableSignaturePublicKeyRef(public_key).delete::<C>(self.connection.borrow())
    }

    fn delete_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        StorableEncryptionPublicKeyRef(public_key).delete::<C>(self.connection.borrow())
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        StorableGroupIdRef(group_id).delete_epoch_key_pair::<C, _>(
            self.connection.borrow(),
            epoch,
            leaf_index,
        )
    }

    fn delete_key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        StorableHashRef(hash_ref).delete_key_package::<C>(self.connection.borrow())
    }

    fn delete_psk<PskKey: openmls_traits::storage::traits::PskId<STORAGE_PROVIDER_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        StorablePskIdRef(psk_id).delete::<C>(self.connection.borrow())
    }
}

#[derive(Serialize, Deserialize)]
struct Aad(Vec<u8>);

impl Entity<STORAGE_PROVIDER_VERSION> for Aad {}
