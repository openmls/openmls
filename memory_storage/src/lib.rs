use openmls_traits::storage::*;
use serde::Serialize;
use std::{collections::HashMap, sync::RwLock};

#[cfg(feature = "test-utils")]
use std::io::Write as _;

/// A storage for the V_TEST version.
#[cfg(any(test, feature = "test-utils"))]
mod test_store;

#[cfg(feature = "persistence")]
pub mod persistence;

mod per_group_locking;
pub use per_group_locking::{MemoryStorageGuard, MemoryStorageManager};

#[derive(Debug, Default)]
pub(crate) struct MemoryStorageInner {
    pub(crate) values: RwLock<HashMap<Vec<u8>, Vec<u8>>>,
}

#[derive(Debug)]
struct SerializedGroupIdRef<'a> {
    bytes: &'a [u8],
}

// For testing we want to clone.
#[cfg(feature = "test-utils")]
impl Clone for MemoryStorageInner {
    fn clone(&self) -> Self {
        let values = self.values.read().unwrap();
        Self {
            values: RwLock::new(values.clone()),
        }
    }
}

// For testing (KATs in particular) we want to serialize and deserialize the storage
#[cfg(feature = "test-utils")]
impl MemoryStorageInner {
    pub fn serialize(&self, w: &mut Vec<u8>) -> std::io::Result<usize> {
        let values = self.values.read().unwrap();

        let mut written = 8;
        let count = (values.len() as u64).to_be_bytes();
        w.write_all(&count)?;

        for (k, v) in values.iter() {
            let rec_len = 8 + 8 + k.len() + v.len();
            let k_len = (k.len() as u64).to_be_bytes();
            let v_len = (v.len() as u64).to_be_bytes();

            w.write_all(&k_len)?;
            w.write_all(&v_len)?;
            w.write_all(k)?;
            w.write_all(v)?;

            written += rec_len;
        }

        Ok(written)
    }

    pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<Self> {
        let read_u64 = |r: &mut R| {
            let mut buf8 = [0u8; 8];
            r.read_exact(&mut buf8).map(|_| u64::from_be_bytes(buf8))
        };

        let read_bytes = |r: &mut R, len: usize| {
            let mut buf = vec![0u8; len];
            r.read_exact(&mut buf).map(|_| buf)
        };

        let mut count = read_u64(r)? as usize;
        let mut map = HashMap::new();

        while count > 0 {
            let k_len = read_u64(r)? as usize;
            let v_len = read_u64(r)? as usize;
            let k = read_bytes(r, k_len)?;
            let v = read_bytes(r, v_len)?;

            map.insert(k, v);
            count -= 1;
        }

        Ok(Self {
            values: RwLock::new(map),
        })
    }
}

impl MemoryStorageGuard<'_> {
    /// Internal helper to abstract write operations.
    #[inline(always)]
    fn write<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.storage.values.write().unwrap();
        let storage_key = build_key_from_vec::<VERSION>(label, key.to_vec());

        #[cfg(feature = "test-utils")]
        log::debug!("  write key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        values.insert(storage_key, value.to_vec());
        Ok(())
    }

    fn append<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.storage.values.write().unwrap();
        let storage_key = build_key_from_vec::<VERSION>(label, key.to_vec());

        #[cfg(feature = "test-utils")]
        log::debug!("  write key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        // fetch value from db, falling back to an empty list if doens't exist
        let list_bytes = values.entry(storage_key).or_insert(b"[]".to_vec());

        // parse old value and push new data
        let mut list: Vec<Vec<u8>> = serde_json::from_slice(list_bytes)?;
        list.push(value);

        // write back, reusing the old buffer
        list_bytes.truncate(0);
        serde_json::to_writer(list_bytes, &list)?;

        Ok(())
    }

    fn remove_item<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.storage.values.write().unwrap();
        let storage_key = build_key_from_vec::<VERSION>(label, key.to_vec());

        #[cfg(feature = "test-utils")]
        log::debug!("  write key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        // fetch value from db, falling back to an empty list if doens't exist
        let list_bytes = values.entry(storage_key).or_insert(b"[]".to_vec());

        // parse old value, find value to delete and remove it from list
        let mut list: Vec<Vec<u8>> = serde_json::from_slice(list_bytes)?;
        if let Some(pos) = list.iter().position(|stored_item| stored_item == &value) {
            list.remove(pos);
        }

        // write back, reusing the old buffer
        list_bytes.truncate(0);
        serde_json::to_writer(list_bytes, &list)?;

        Ok(())
    }

    /// Internal helper to abstract read operations.
    #[inline(always)]
    fn read<const VERSION: u16, V: Entity<VERSION>>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<V>, <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let values = self.storage.values.read().unwrap();
        let storage_key = build_key_from_vec::<VERSION>(label, key.to_vec());

        #[cfg(feature = "test-utils")]
        log::debug!("  read key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        let value = values.get(&storage_key);

        if let Some(value) = value {
            serde_json::from_slice(value)
                .map_err(|_| MemoryStorageError::SerializationError)
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
        let values = self.storage.values.read().unwrap();

        let mut storage_key = label.to_vec();
        storage_key.extend_from_slice(key);
        storage_key.extend_from_slice(&u16::to_be_bytes(VERSION));

        #[cfg(feature = "test-utils")]
        log::debug!("  read list key: {}", hex::encode(&storage_key));
        log::trace!("{}", std::backtrace::Backtrace::capture());

        let value: Vec<Vec<u8>> = match values.get(&storage_key) {
            Some(list_bytes) => serde_json::from_slice(list_bytes).unwrap(),
            None => vec![],
        };

        value
            .iter()
            .map(|value_bytes| serde_json::from_slice(value_bytes))
            .collect::<Result<Vec<V>, _>>()
            .map_err(|_| MemoryStorageError::SerializationError)
    }

    /// Internal helper to abstract delete operations.
    #[inline(always)]
    fn delete<const VERSION: u16>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<(), <Self as StorageProvider<CURRENT_VERSION>>::Error> {
        let mut values = self.storage.values.write().unwrap();

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
pub enum MemoryStorageError {
    #[error("The key store does not allow storing serialized values.")]
    UnsupportedValueTypeBytes,
    #[error("Updating is not supported by this key store.")]
    UnsupportedMethod,
    #[error("Error serializing value.")]
    SerializationError,

    #[error("Error acquiring lock for GroupId.")]
    LockError,
}

const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
const PSK_LABEL: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";

// related to PublicGroup
const TREE_LABEL: &[u8] = b"Tree";
const GROUP_CONTEXT_LABEL: &[u8] = b"GroupContext";
#[cfg(feature = "extensions-draft-08")]
const APPLICATION_EXPORT_TREE_LABEL: &[u8] = b"ApplicationExportTree";
const INTERIM_TRANSCRIPT_HASH_LABEL: &[u8] = b"InterimTranscriptHash";
const CONFIRMATION_TAG_LABEL: &[u8] = b"ConfirmationTag";

// related to MlsGroup
const JOIN_CONFIG_LABEL: &[u8] = b"MlsGroupJoinConfig";
const OWN_LEAF_NODES_LABEL: &[u8] = b"OwnLeafNodes";
const GROUP_STATE_LABEL: &[u8] = b"GroupState";
const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
const PROPOSAL_QUEUE_REFS_LABEL: &[u8] = b"ProposalQueueRefs";
const OWN_LEAF_NODE_INDEX_LABEL: &[u8] = b"OwnLeafNodeIndex";
const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";

impl StorageProvider<CURRENT_VERSION> for MemoryStorageGuard<'_> {
    type Error = MemoryStorageError;

    fn queue_proposal<
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,

        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        // write proposal to key (group_id, proposal_ref)
        let key = proposal_ref_key(&self.serialized_group_id, proposal_ref)?;
        let value = serde_json::to_vec(proposal)?;
        self.write::<CURRENT_VERSION>(QUEUED_PROPOSAL_LABEL, &key, value)?;

        // update proposal list for group_id
        let key = self.serialized_group_id.bytes;
        let value = serde_json::to_vec(proposal_ref)?;
        self.append::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;

        Ok(())
    }

    fn write_tree<TreeSync: traits::TreeSync<CURRENT_VERSION>>(
        &self,

        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            TREE_LABEL,
            &self.serialized_group_id.bytes,
            serde_json::to_vec(&tree).unwrap(),
        )
    }

    fn write_interim_transcript_hash<
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,

        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        let mut values = self.storage.values.write().unwrap();
        let key = build_key_from_vec::<CURRENT_VERSION>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            self.serialized_group_id.bytes.to_vec(),
        );
        let value = serde_json::to_vec(&interim_transcript_hash).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_context<GroupContext: traits::GroupContext<CURRENT_VERSION>>(
        &self,

        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        let mut values = self.storage.values.write().unwrap();
        let key = build_key_from_vec::<CURRENT_VERSION>(
            GROUP_CONTEXT_LABEL,
            self.serialized_group_id.bytes.to_vec(),
        );
        let value = serde_json::to_vec(&group_context).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn write_confirmation_tag<ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>>(
        &self,

        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        let mut values = self.storage.values.write().unwrap();
        let key = build_key_from_vec::<CURRENT_VERSION>(
            CONFIRMATION_TAG_LABEL,
            self.serialized_group_id.bytes.to_vec(),
        );
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
        let mut values = self.storage.values.write().unwrap();
        let key =
            build_key::<CURRENT_VERSION, &SignaturePublicKey>(SIGNATURE_KEY_PAIR_LABEL, public_key);
        let value = serde_json::to_vec(&signature_key_pair).unwrap();

        values.insert(key, value);
        Ok(())
    }

    fn queued_proposal_refs<ProposalRef: traits::ProposalRef<CURRENT_VERSION>>(
        &self,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list(PROPOSAL_QUEUE_REFS_LABEL, &self.serialized_group_id.bytes)
    }

    fn queued_proposals<
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> =
            self.read_list(PROPOSAL_QUEUE_REFS_LABEL, &self.serialized_group_id.bytes)?;

        refs.into_iter()
            .map(|proposal_ref| -> Result<_, _> {
                let key = proposal_ref_key(&self.serialized_group_id, &proposal_ref)?;

                let proposal = self.read(QUEUED_PROPOSAL_LABEL, &key)?.unwrap();
                Ok((proposal_ref, proposal))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    fn tree<TreeSync: traits::TreeSync<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<TreeSync>, Self::Error> {
        let values = self.storage.values.read().unwrap();
        let key = build_key_from_vec::<CURRENT_VERSION>(
            TREE_LABEL,
            self.serialized_group_id.bytes.to_vec(),
        );

        let Some(value) = values.get(&key) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn group_context<GroupContext: traits::GroupContext<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<GroupContext>, Self::Error> {
        let values = self.storage.values.read().unwrap();
        let key = build_key_from_vec::<CURRENT_VERSION>(
            GROUP_CONTEXT_LABEL,
            self.serialized_group_id.bytes.to_vec(),
        );

        let Some(value) = values.get(&key) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn interim_transcript_hash<
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        let values = self.storage.values.read().unwrap();
        let key = build_key_from_vec::<CURRENT_VERSION>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            self.serialized_group_id.bytes.to_vec(),
        );

        let Some(value) = values.get(&key) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    fn confirmation_tag<ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        let values = self.storage.values.read().unwrap();
        let key = build_key_from_vec::<CURRENT_VERSION>(
            CONFIRMATION_TAG_LABEL,
            self.serialized_group_id.bytes.to_vec(),
        );

        let Some(value) = values.get(&key) else {
            return Ok(None);
        };
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
        let values = self.storage.values.read().unwrap();

        let key =
            build_key::<CURRENT_VERSION, &SignaturePublicKey>(SIGNATURE_KEY_PAIR_LABEL, public_key);

        let Some(value) = values.get(&key) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
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

        self.write::<CURRENT_VERSION>(KEY_PACKAGE_LABEL, &key, value)
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
            serde_json::to_vec(&psk).unwrap(),
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
            serde_json::to_vec(key_pair).unwrap(),
        )
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        let key = serde_json::to_vec(&hash_ref).unwrap();
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
        self.delete::<CURRENT_VERSION>(KEY_PACKAGE_LABEL, &serde_json::to_vec(&hash_ref)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(PSK_LABEL, &serde_json::to_vec(&psk_id)?)
    }

    fn group_state<GroupState: traits::GroupState<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read(GROUP_STATE_LABEL, &self.serialized_group_id.bytes)
    }

    fn write_group_state<GroupState: traits::GroupState<CURRENT_VERSION>>(
        &self,

        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            GROUP_STATE_LABEL,
            &self.serialized_group_id.bytes,
            serde_json::to_vec(group_state)?,
        )
    }

    fn delete_group_state(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(GROUP_STATE_LABEL, &self.serialized_group_id.bytes)
    }

    fn message_secrets<MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read(MESSAGE_SECRETS_LABEL, &self.serialized_group_id.bytes)
    }

    fn write_message_secrets<MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>>(
        &self,

        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            MESSAGE_SECRETS_LABEL,
            &self.serialized_group_id.bytes,
            serde_json::to_vec(message_secrets)?,
        )
    }

    fn delete_message_secrets(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(MESSAGE_SECRETS_LABEL, &self.serialized_group_id.bytes)
    }

    fn resumption_psk_store<ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read(RESUMPTION_PSK_STORE_LABEL, &self.serialized_group_id.bytes)
    }

    fn write_resumption_psk_store<
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,

        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            RESUMPTION_PSK_STORE_LABEL,
            &self.serialized_group_id.bytes,
            serde_json::to_vec(resumption_psk_store)?,
        )
    }

    fn delete_all_resumption_psk_secrets(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(RESUMPTION_PSK_STORE_LABEL, &self.serialized_group_id.bytes)
    }

    fn own_leaf_index<LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read(OWN_LEAF_NODE_INDEX_LABEL, &self.serialized_group_id.bytes)
    }

    fn write_own_leaf_index<LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>>(
        &self,

        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            OWN_LEAF_NODE_INDEX_LABEL,
            &self.serialized_group_id.bytes,
            serde_json::to_vec(own_leaf_index)?,
        )
    }

    fn delete_own_leaf_index(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(OWN_LEAF_NODE_INDEX_LABEL, &self.serialized_group_id.bytes)
    }

    fn group_epoch_secrets<GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read(EPOCH_SECRETS_LABEL, &self.serialized_group_id.bytes)
    }

    fn write_group_epoch_secrets<GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>>(
        &self,

        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            EPOCH_SECRETS_LABEL,
            &self.serialized_group_id.bytes,
            serde_json::to_vec(group_epoch_secrets)?,
        )
    }

    fn delete_group_epoch_secrets(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(EPOCH_SECRETS_LABEL, &self.serialized_group_id.bytes)
    }

    fn write_encryption_epoch_key_pairs<
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,

        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(&self.serialized_group_id, epoch, leaf_index)?;
        let value = serde_json::to_vec(key_pairs)?;
        log::debug!("Writing encryption epoch key pairs");
        #[cfg(feature = "test-utils")]
        {
            log::debug!("  key: {}", hex::encode(&key));
            log::debug!("  value: {}", hex::encode(&value));
        }

        self.write::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key, value)
    }

    fn encryption_epoch_key_pairs<
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,

        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_id(&self.serialized_group_id, epoch, leaf_index)?;
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, key);
        log::debug!("Reading encryption epoch key pairs");

        let values = self.storage.values.read().unwrap();
        let value = values.get(&storage_key);

        #[cfg(feature = "test-utils")]
        log::debug!("  key: {}", hex::encode(&storage_key));

        if let Some(value) = value {
            #[cfg(feature = "test-utils")]
            log::debug!("  value: {}", hex::encode(value));
            return Ok(serde_json::from_slice(value).unwrap());
        }

        Ok(vec![])
    }

    fn delete_encryption_epoch_key_pairs<EpochKey: traits::EpochKey<CURRENT_VERSION>>(
        &self,

        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id(&self.serialized_group_id, epoch, leaf_index)?;
        self.delete::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key)
    }

    fn clear_proposal_queue<ProposalRef: traits::ProposalRef<CURRENT_VERSION>>(
        &self,
    ) -> Result<(), Self::Error> {
        // Get all proposal refs for this group.
        let proposal_refs: Vec<ProposalRef> =
            self.read_list(PROPOSAL_QUEUE_REFS_LABEL, &self.serialized_group_id.bytes)?;
        let mut values = self.storage.values.write().unwrap();
        for proposal_ref in proposal_refs {
            // Delete all proposals.
            let key = proposal_ref_key(&self.serialized_group_id, &proposal_ref)?;
            values.remove(&key);
        }

        // Delete the proposal refs from the store.
        let key = build_key_from_vec::<CURRENT_VERSION>(
            PROPOSAL_QUEUE_REFS_LABEL,
            self.serialized_group_id.bytes.to_vec(),
        );
        values.remove(&key);

        Ok(())
    }

    fn mls_group_join_config<MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>>(
        &self,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read(JOIN_CONFIG_LABEL, &self.serialized_group_id.bytes)
    }

    fn write_mls_join_config<MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>>(
        &self,

        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        let key = self.serialized_group_id.bytes;
        let value = serde_json::to_vec(config).unwrap();

        self.write::<CURRENT_VERSION>(JOIN_CONFIG_LABEL, &key, value)
    }

    fn own_leaf_nodes<LeafNode: traits::LeafNode<CURRENT_VERSION>>(
        &self,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list(OWN_LEAF_NODES_LABEL, &self.serialized_group_id.bytes)
    }

    fn append_own_leaf_node<LeafNode: traits::LeafNode<CURRENT_VERSION>>(
        &self,

        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        let key = self.serialized_group_id.bytes;
        let value = serde_json::to_vec(leaf_node)?;
        self.append::<CURRENT_VERSION>(OWN_LEAF_NODES_LABEL, &key, value)
    }

    fn delete_own_leaf_nodes(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(OWN_LEAF_NODES_LABEL, &self.serialized_group_id.bytes)
    }

    fn delete_group_config(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(JOIN_CONFIG_LABEL, &self.serialized_group_id.bytes)
    }

    fn delete_tree(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(TREE_LABEL, &self.serialized_group_id.bytes)
    }

    fn delete_confirmation_tag(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(CONFIRMATION_TAG_LABEL, &self.serialized_group_id.bytes)
    }

    fn delete_context(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(GROUP_CONTEXT_LABEL, &self.serialized_group_id.bytes)
    }

    fn delete_interim_transcript_hash(&self) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &self.serialized_group_id.bytes,
        )
    }

    fn remove_proposal<ProposalRef: traits::ProposalRef<CURRENT_VERSION>>(
        &self,

        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let key = self.serialized_group_id.bytes;
        let value = serde_json::to_vec(proposal_ref).unwrap();

        self.remove_item::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;

        let key = proposal_ref_key(&self.serialized_group_id, proposal_ref)?;
        self.delete::<CURRENT_VERSION>(QUEUED_PROPOSAL_LABEL, &key)
    }

    #[cfg(feature = "extensions-draft-08")]
    fn write_application_export_tree<
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,

        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        self.write::<CURRENT_VERSION>(
            APPLICATION_EXPORT_TREE_LABEL,
            &self.serialized_group_id,
            serde_json::to_vec(&application_export_tree).unwrap(),
        )
    }

    #[cfg(feature = "extensions-draft-08")]
    fn application_export_tree<
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        let values = self.storage.values.read().unwrap();
        let key = build_key::<CURRENT_VERSION, &GroupId>(APPLICATION_EXPORT_TREE_LABEL, group_id);

        let Some(value) = values.get(&key) else {
            return Ok(None);
        };
        let value = serde_json::from_slice(value).unwrap();

        Ok(value)
    }

    #[cfg(feature = "extensions-draft-08")]
    fn delete_application_export_tree<
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
    ) -> Result<(), Self::Error> {
        self.delete::<CURRENT_VERSION>(APPLICATION_EXPORT_TREE_LABEL, self.serialized_group_id)
    }
}

/// Build a key with version and label.
fn build_key_from_vec<const V: u16>(label: &[u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    let mut key_out = label.to_vec();
    key_out.extend_from_slice(key.as_ref());
    key_out.extend_from_slice(&u16::to_be_bytes(V));
    key_out
}

/// Build a key with version and label.
fn build_key<const V: u16, K: Serialize>(label: &[u8], key: K) -> Vec<u8> {
    build_key_from_vec::<V>(label, serde_json::to_vec(&key).unwrap())
}

fn epoch_key_pairs_id<'a>(
    serialized_group_id: &'a SerializedGroupIdRef<'a>,
    epoch: &impl traits::EpochKey<CURRENT_VERSION>,
    leaf_index: u32,
) -> Result<Vec<u8>, <MemoryStorageGuard<'a> as StorageProvider<CURRENT_VERSION>>::Error> {
    let mut key = serialized_group_id.bytes.to_vec();
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}

fn proposal_ref_key<ProposalRef: traits::ProposalRef<CURRENT_VERSION>>(
    serialized_group_id: &SerializedGroupIdRef<'_>,
    proposal_ref: &ProposalRef,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut key = serialized_group_id.bytes.to_vec();
    key.extend_from_slice(&serde_json::to_vec(proposal_ref)?);
    Ok(key)
}

impl From<serde_json::Error> for MemoryStorageError {
    fn from(_: serde_json::Error) -> Self {
        Self::SerializationError
    }
}
