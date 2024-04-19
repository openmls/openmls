use openmls_traits::storage::*;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, io::Write as _, sync::RwLock};

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct MemoryKeyStore {
    values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

impl MemoryKeyStore {
    /// Internal helper to abstract write operations.
    #[inline(always)]
    fn write<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: &[u8],
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.values.write().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        #[cfg(feature = "test-utils")]
        log::debug!("  write key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        values.insert(storage_key, value.to_vec());
        Ok(())
    }

    /// Internal helper to abstract read operations.
    #[inline(always)]
    fn read<const VERSION: u16, V: Entity<VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<V>, <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let values = self.values.read().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        #[cfg(feature = "test-utils")]
        log::debug!("  read key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        let value = values.get(&storage_key);

        if let Some(value) = value {
            serde_json::from_slice(value)
                .map_err(|_| MemoryKeyStoreError::SerializationError)
                .map(|v| Some(v))
        } else {
            Ok(None)
        }
    }

    /// Internal helper to abstract read operations.
    #[inline(always)]
    fn read_list<const VERSION: u16, V: Entity<VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Vec<V>, <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let values = self.values.read().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        #[cfg(feature = "test-utils")]
        log::debug!("  read list key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        let value = values.get(&storage_key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    /// Internal helper to abstract delete operations.
    #[inline(always)]
    fn delete<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.values.write().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        #[cfg(feature = "test-utils")]
        log::debug!("  delete key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        values.remove(&storage_key);

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

const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
const INIT_KEY_LABEL: &[u8] = b"HpkePrivateKey";
const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
const TREE_LABEL: &[u8] = b"Tree";
const PSK_LABEL: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";

const OWN_LEAF_NODE_LABEL: &[u8] = b"OwnLeafNode";
const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";
const GROUP_STATE_LABEL: &[u8] = b"GroupState";
const USE_RATCHET_TREE_LABEL: &[u8] = b"UseRatchetTree";

impl StorageProvider<CURRENT_VERSION> for MemoryKeyStore {
    type Error = MemoryKeyStoreError;
    // type Types = Types;

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
        let mut values = self.values.write().unwrap();

        let mut key = QUEUED_PROPOSAL_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let proposals = values.get_mut(&key);
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

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            TREE_LABEL,
            &serde_json::to_vec(&group_id).unwrap(),
            &serde_json::to_vec(&tree).unwrap(),
        )
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        let mut key = b"InterimTranscriptHash".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&interim_transcript_hash).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        let mut key = b"GroupContext".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&group_context).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        let mut key = b"ConfirmationTag".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&confirmation_tag).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();
        let mut key = SIGNATURE_KEY_PAIR_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(&signature_key_pair).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        let values = self.values.read().unwrap();

        let mut key = b"ProposalRef".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        // XXX: This is wrong.
        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(vec![value])
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<QueuedProposal>, Self::Error> {
        let values = self.values.read().unwrap();

        let mut key = QUEUED_PROPOSAL_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(vec![value])
    }

    fn treesync<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        let values = self.values.read().unwrap();

        // XXX: These domain separators should be constants.
        let mut key = b"Tree".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        let values = self.values.read().unwrap();

        let mut key = b"GroupContext".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        let values = self.values.read().unwrap();

        let mut key = b"InterimTranscriptHash".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        let values = self.values.read().unwrap();

        let mut key = b"ConfirmationTag".to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        let values = self.values.read().unwrap();

        let mut key = SIGNATURE_KEY_PAIR_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key).unwrap();
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn write_init_private_key<
        InitKey: traits::InitKey<CURRENT_VERSION>,
        HpkePrivateKey: traits::HpkePrivateKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &InitKey,
        private_key: &HpkePrivateKey,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();

        let mut key = INIT_KEY_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));
        let value = serde_json::to_vec(private_key).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(&hash_ref).unwrap();
        let value = serde_json::to_vec(&key_package).unwrap();

        self.write::<CURRENT_VERSION>(KEY_PACKAGE_LABEL, &key, &value)
            .unwrap();

        Ok(())
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            PSK_LABEL,
            &serde_json::to_vec(&psk_id).unwrap(),
            &serde_json::to_vec(&psk).unwrap(),
        )
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).unwrap(),
            &serde_json::to_vec(key_pair).unwrap(),
        )
    }

    fn init_private_key<
        InitKey: traits::InitKey<CURRENT_VERSION>,
        HpkePrivateKey: traits::HpkePrivateKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &InitKey,
    ) -> Result<Option<HpkePrivateKey>, Self::Error> {
        let values = self.values.read().unwrap();

        let mut key = INIT_KEY_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&key);

        if let Some(value) = value {
            serde_json::from_slice(value).map_err(|_| MemoryKeyStoreError::SerializationError)
        } else {
            Ok(None)
        }
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let key = serde_json::to_vec(&hash_ref).unwrap();

        println!("getting key package at {key:?} for version {CURRENT_VERSION}");
        println!(
            "the whole store when trying to get the key package: {:?}",
            self.values.read().unwrap()
        );
        self.read(KEY_PACKAGE_LABEL, &key)
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read(PSK_LABEL, &serde_json::to_vec(&psk_id).unwrap())
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).unwrap(),
        )
    }

    fn delete_signature_key_pair<
        SignaturePublicKeuy: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKeuy,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key).unwrap(),
        )
    }

    fn delete_init_private_key<InitKey: traits::InitKey<CURRENT_VERSION>>(
        &self,
        public_key: &InitKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(INIT_KEY_LABEL, &serde_json::to_vec(public_key).unwrap())
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(&public_key).unwrap(),
        )
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(KEY_PACKAGE_LABEL, &serde_json::to_vec(&hash_ref).unwrap())
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(PSK_LABEL, &serde_json::to_vec(&psk_id).unwrap())
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        todo!()
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id)?,
            &serde_json::to_vec(group_state)?,
        )
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        todo!()
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            &serde_json::to_vec(message_secrets)?,
        )
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        todo!()
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
            &serde_json::to_vec(resumption_psk_store)?,
        )
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        todo!()
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            OWN_LEAF_NODE_LABEL,
            &serde_json::to_vec(group_id)?,
            &serde_json::to_vec(own_leaf_index)?,
        )
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn use_ratchet_tree_extension<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<bool>, Self::Error> {
        todo!()
    }

    fn set_use_ratchet_tree_extension<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
        value: bool,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            USE_RATCHET_TREE_LABEL,
            &serde_json::to_vec(group_id)?,
            &serde_json::to_vec(&value)?,
        )
    }

    fn delete_use_ratchet_tree_extension<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        todo!()
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            &serde_json::to_vec(group_epoch_secrets)?,
        )
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
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
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        let value = serde_json::to_vec(key_pairs)?;
        log::debug!("Writing encryption epoch key pairs");
        #[cfg(feature = "test-utils")]
        {
            log::debug!("  key: {}", hex::encode(&key));
            log::debug!("  value: {}", hex::encode(&value));
        }

        self.write::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key, &value)
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
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        log::debug!("Reading encryption epoch key pairs");

        let values = self.values.read().unwrap();

        let mut storage_key = EPOCH_KEY_PAIRS_LABEL.to_vec();
        storage_key.extend_from_slice(&key);
        storage_key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        let value = values.get(&storage_key);

        #[cfg(feature = "test-utils")]
        log::debug!("  key: {}", hex::encode(&storage_key));

        if let Some(value) = value {
            #[cfg(feature = "test-utils")]
            log::debug!("  value: {}", hex::encode(&value));
            return Ok(serde_json::from_slice(value).unwrap());
        }

        Err(MemoryKeyStoreError::None)
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
        let key = epoch_key_pairs_id(group_id, epoch, leaf_index)?;
        self.delete::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key)
    }

    fn clear_proposal_queue<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();

        let mut key = QUEUED_PROPOSAL_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&group_id).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(CURRENT_VERSION));

        // XXX: also remove the proposal refs. can't be done now because they are stored in a
        // non-recoverable way
        values.remove(&key);

        Ok(())
    }
}

fn epoch_key_pairs_id(
    group_id: &impl traits::GroupId<CURRENT_VERSION>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, <MemoryKeyStore as StorageProvider<CURRENT_VERSION>>::Error> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

#[cfg(feature = "test-utils")]
impl StorageProvider<V_TEST> for MemoryKeyStore {
    type Error = MemoryKeyStoreError;

    fn write_init_private_key<
        InitKey: traits::InitKey<V_TEST>,
        HpkePrivateKey: traits::HpkePrivateKey<V_TEST>,
    >(
        &self,
        public_key: &InitKey,
        private_key: &HpkePrivateKey,
    ) -> Result<(), Self::Error> {
        let mut values = self.values.write().unwrap();

        let mut key = INIT_KEY_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(V_TEST));
        let value = serde_json::to_vec(private_key).unwrap();

        values.insert(key, value);
        Ok(())
    }

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
            &serde_json::to_vec(&key_pair).unwrap(),
        )
    }

    fn init_private_key<
        InitKey: traits::InitKey<V_TEST>,
        HpkePrivateKey: traits::HpkePrivateKey<V_TEST>,
    >(
        &self,
        public_key: &InitKey,
    ) -> Result<Option<HpkePrivateKey>, Self::Error> {
        let values = self.values.read().unwrap();

        let mut key = INIT_KEY_LABEL.to_vec();
        key.extend_from_slice(&serde_json::to_vec(&public_key).unwrap());
        key.extend_from_slice(&u16::to_be_bytes(V_TEST));
        let value = values.get(&key).ok_or(MemoryKeyStoreError::None)?;

        serde_json::from_slice(value).map_err(|_| MemoryKeyStoreError::SerializationError)
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

        self.write::<V_TEST>(KEY_PACKAGE_LABEL, &key, &value)
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
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_tree<GroupId: traits::GroupId<V_TEST>, TreeSync: traits::TreeSync<V_TEST>>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<V_TEST>,
        InterimTranscriptHash: traits::InterimTranscriptHash<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_context<
        GroupId: traits::GroupId<V_TEST>,
        GroupContext: traits::GroupContext<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<V_TEST>,
        ConfirmationTag: traits::ConfirmationTag<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<V_TEST>,
        SignatureKeyPair: traits::SignatureKeyPair<V_TEST>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V_TEST>,
        EpochKey: traits::EpochKey<V_TEST>,
        HpkeKeyPair: traits::HpkeKeyPair<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn write_psk<PskId: traits::PskId<V_TEST>, PskBundle: traits::PskBundle<V_TEST>>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<V_TEST>,
        ProposalRef: traits::ProposalRef<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        todo!()
    }

    fn queued_proposals<
        GroupId: traits::GroupId<V_TEST>,
        QueuedProposal: traits::QueuedProposal<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<QueuedProposal>, Self::Error> {
        todo!()
    }

    fn treesync<GroupId: traits::GroupId<V_TEST>, TreeSync: traits::TreeSync<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        todo!()
    }

    fn group_context<
        GroupId: traits::GroupId<V_TEST>,
        GroupContext: traits::GroupContext<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        todo!()
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<V_TEST>,
        InterimTranscriptHash: traits::InterimTranscriptHash<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        todo!()
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<V_TEST>,
        ConfirmationTag: traits::ConfirmationTag<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        todo!()
    }

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<V_TEST>,
        SignatureKeyPair: traits::SignatureKeyPair<V_TEST>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        todo!()
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<V_TEST>,
        EncryptionKey: traits::EncryptionKey<V_TEST>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        todo!()
    }

    fn psk<PskBundle: traits::PskBundle<V_TEST>, PskId: traits::PskId<V_TEST>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        todo!()
    }

    fn delete_signature_key_pair<SignaturePublicKeuy: traits::SignaturePublicKey<V_TEST>>(
        &self,
        public_key: &SignaturePublicKeuy,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_init_private_key<InitKey: traits::InitKey<V_TEST>>(
        &self,
        public_key: &InitKey,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<V_TEST>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<V_TEST>,
        EpochKey: traits::EpochKey<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<V_TEST>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_psk<PskKey: traits::PskId<V_TEST>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn group_state<GroupState: traits::GroupState<V_TEST>, GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        todo!()
    }

    fn write_group_state<
        GroupState: traits::GroupState<V_TEST>,
        GroupId: traits::GroupId<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_state<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn message_secrets<
        GroupId: traits::GroupId<V_TEST>,
        MessageSecrets: traits::MessageSecrets<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        todo!()
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<V_TEST>,
        MessageSecrets: traits::MessageSecrets<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_message_secrets<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<V_TEST>,
        ResumptionPskStore: traits::ResumptionPskStore<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        todo!()
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<V_TEST>,
        ResumptionPskStore: traits::ResumptionPskStore<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<V_TEST>,
        LeafNodeIndex: traits::LeafNodeIndex<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        todo!()
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<V_TEST>,
        LeafNodeIndex: traits::LeafNodeIndex<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn use_ratchet_tree_extension<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<bool>, Self::Error> {
        todo!()
    }

    fn set_use_ratchet_tree_extension<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
        value: bool,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_use_ratchet_tree_extension<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<V_TEST>,
        GroupEpochSecrets: traits::GroupEpochSecrets<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        todo!()
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<V_TEST>,
        GroupEpochSecrets: traits::GroupEpochSecrets<V_TEST>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }

    fn clear_proposal_queue<GroupId: traits::GroupId<V_TEST>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        todo!()
    }
}

impl From<serde_json::Error> for MemoryKeyStoreError {
    fn from(_: serde_json::Error) -> Self {
        Self::SerializationError
    }
}
