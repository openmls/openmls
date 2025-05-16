use std::{
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    ops::{Deref, DerefMut},
    sync::{Arc, Mutex},
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
    pub(super) epoch: Vec<u8>,
    pub(super) connection: Arc<Mutex<ConnectionRef>>,
    _codec: PhantomData<C>,
}

impl<C: Codec, ConnectionRef: Borrow<Connection>> SqliteStorageProvider<C, ConnectionRef> {
    /// Create a new instance of the [`SqliteStorageProvider`].
    pub fn new(connection: ConnectionRef) -> Self {
        Self {
            epoch: Vec::new(),
            connection: Arc::new(connection.into()),
            _codec: PhantomData,
        }
    }

    pub fn clone_with_epoch(&self, epoch: Vec<u8>) -> Self {
        Self {
            epoch,
            connection: self.connection.clone(),
            _codec: PhantomData,
        }
    }
}

impl<C: Codec, ConnectionRef: BorrowMut<Connection>> SqliteStorageProvider<C, ConnectionRef> {
    /// Initialize the database with the necessary tables.
    pub fn initialize(&mut self) -> Result<(), refinery::Error> {
        let mut connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref_mut().borrow_mut();
        migrations::runner().run(connection)?;
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(config).store::<C, _>(
            connection,
            group_id,
            GroupDataType::JoinGroupConfig,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableLeafNodeRef(leaf_node).store::<C, _>(connection, group_id, &self.epoch)
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableProposalRef(proposal_ref, proposal).store::<C, _>(connection, group_id, &self.epoch)
    }

    fn write_tree<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        println!("Storing tree for epoch {:?}", self.epoch);
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(tree).store::<C, _>(
            connection,
            group_id,
            GroupDataType::Tree,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(interim_transcript_hash).store::<C, _>(
            connection,
            group_id,
            GroupDataType::InterimTranscriptHash,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(group_context).store::<C, _>(
            connection,
            group_id,
            GroupDataType::Context,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(confirmation_tag).store::<C, _>(
            connection,
            group_id,
            GroupDataType::ConfirmationTag,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(group_state).store::<C, _>(
            connection,
            group_id,
            GroupDataType::GroupState,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(message_secrets).store::<C, _>(
            connection,
            group_id,
            GroupDataType::MessageSecrets,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(resumption_psk_store).store::<C, _>(
            connection,
            group_id,
            GroupDataType::ResumptionPskStore,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(own_leaf_index).store::<C, _>(
            connection,
            group_id,
            GroupDataType::OwnLeafIndex,
            &self.epoch,
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
        println!("Storing group epoch secrets for epoch {:?}", self.epoch);
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupDataRef(group_epoch_secrets).store::<C, _>(
            connection,
            group_id,
            GroupDataType::GroupEpochSecrets,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableSignatureKeyPairsRef(signature_key_pair).store::<C, _>(connection, public_key)
    }

    fn write_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableEncryptionKeyPairRef(key_pair).store::<C, _>(connection, public_key, &self.epoch)
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableEpochKeyPairsRef(key_pairs).store::<C, _, _>(
            connection,
            group_id,
            epoch,
            leaf_index,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableKeyPackageRef(key_package).store::<C, _>(connection, hash_ref)
    }

    fn write_psk<
        PskId: openmls_traits::storage::traits::PskId<STORAGE_PROVIDER_VERSION>,
        PskBundle: openmls_traits::storage::traits::PskBundle<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorablePskBundleRef(psk).store::<C, _>(connection, psk_id)
    }

    fn mls_group_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(
            connection,
            group_id,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableLeafNode::load::<C, _>(connection, group_id, &self.epoch)
    }

    fn queued_proposal_refs<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableProposal::<u8, ProposalRef>::load_refs::<C, _>(connection, group_id, &self.epoch)
    }

    fn queued_proposals<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableProposal::load::<C, _>(connection, group_id, &self.epoch)
    }

    fn tree<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        println!("Loading tree for epoch {:?}", self.epoch);
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        let res =
            StorableGroupData::load::<C, _>(connection, group_id, &self.epoch, GroupDataType::Tree);
        if let Ok(Some(_)) = res {
            println!("Loaded tree for epoch {:?}", self.epoch);
        } else {
            println!("No tree found for epoch {:?}", self.epoch);
        }
        res
    }

    fn group_context<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(connection, group_id, &self.epoch, GroupDataType::Context)
    }

    fn interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(
            connection,
            group_id,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(
            connection,
            group_id,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(
            connection,
            group_id,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(
            connection,
            group_id,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(
            connection,
            group_id,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(
            connection,
            group_id,
            &self.epoch,
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
        println!("Loading group epoch secrets for epoch {:?}", self.epoch);
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupData::load::<C, _>(
            connection,
            group_id,
            &self.epoch,
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableSignatureKeyPairs::load::<C, _>(connection, public_key)
    }

    fn encryption_key_pair<
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<STORAGE_PROVIDER_VERSION>,
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableEncryptionKeyPair::load::<C, _>(connection, public_key, &self.epoch)
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableEpochKeyPairs::load::<C, _, _>(connection, group_id, epoch, leaf_index, &self.epoch)
    }

    fn key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<STORAGE_PROVIDER_VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableKeyPackage::load::<C, _>(connection, hash_ref)
    }

    fn psk<
        PskBundle: openmls_traits::storage::traits::PskBundle<STORAGE_PROVIDER_VERSION>,
        PskId: openmls_traits::storage::traits::PskId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorablePskBundle::load::<C, _>(connection, psk_id)
    }

    fn remove_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_proposal::<C, _>(connection, &self.epoch, proposal_ref)
    }

    fn delete_own_leaf_nodes<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_leaf_nodes::<C>(connection, &self.epoch)
    }

    fn delete_group_config<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::JoinGroupConfig,
            &self.epoch,
        )
    }

    fn delete_tree<GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        println!("Deleting tree for epoch {:?}", self.epoch);
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::Tree,
            &self.epoch,
        )
    }

    fn delete_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::ConfirmationTag,
            &self.epoch,
        )
    }

    fn delete_group_state<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::GroupState,
            &self.epoch,
        )
    }

    fn delete_context<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::Context,
            &self.epoch,
        )
    }

    fn delete_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::InterimTranscriptHash,
            &self.epoch,
        )
    }

    fn delete_message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::MessageSecrets,
            &self.epoch,
        )
    }

    fn delete_all_resumption_psk_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::ResumptionPskStore,
            &self.epoch,
        )
    }

    fn delete_own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::OwnLeafIndex,
            &self.epoch,
        )
    }

    fn delete_group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_group_data::<C>(
            connection,
            GroupDataType::GroupEpochSecrets,
            &self.epoch,
        )
    }

    fn clear_proposal_queue<
        GroupId: openmls_traits::storage::traits::GroupId<STORAGE_PROVIDER_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_all_proposals::<C>(connection, &self.epoch)?;
        Ok(())
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableSignaturePublicKeyRef(public_key).delete::<C>(connection)
    }

    fn delete_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableEncryptionPublicKeyRef(public_key).delete::<C>(connection, &self.epoch)
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
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableGroupIdRef(group_id).delete_epoch_key_pair::<C, _>(
            connection,
            epoch,
            leaf_index,
            &self.epoch,
        )
    }

    fn delete_key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<STORAGE_PROVIDER_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorableHashRef(hash_ref).delete_key_package::<C>(connection)
    }

    fn delete_psk<PskKey: openmls_traits::storage::traits::PskId<STORAGE_PROVIDER_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        let connection_guard = self.connection.lock().unwrap();
        let connection = connection_guard.deref().borrow();
        StorablePskIdRef(psk_id).delete::<C>(connection)
    }
}

#[derive(Serialize, Deserialize)]
struct Aad(Vec<u8>);

impl Entity<STORAGE_PROVIDER_VERSION> for Aad {}
