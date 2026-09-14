//! This module implements a customizable [`OpenMlsProvider`] with storage that
//! delegates methods to a different provider but can inject errors on chosen method calls.
//!
//! It is used to test error handling.
//!
//! Example:
//! ```
//! const TEST_AAD: &[u8] = b"Test AAD";
//!
//! #[openmls_test::openmls_test]
//! fn test_aad_error_commit() {
//!     // Group with Alice
//!     let provider = &Provider::default();
//!     let (mut group, _credential, signer, _pk) = setup_alice_group(ciphersuite, provider);
//!
//!     // Storage provider that will fail to write group state
//!     let test_storage = TestStorageProvider {
//!         delegate: provider.storage(),
//!         errors: RefCell::new(HashMap::from([
//!             // First invocation of [`StorageProvider::write_group_state`] returns custom error.
//!             // Returned errors are popped from the end of the [`Vec`], hence they occur in reverse order.
//!             ("write_group_state", vec![TestStorageError::Injected("writing group state")])
//!         ])),
//!     };
//!     let test_provider = TestProvider {
//!         storage: &test_storage,
//!         crypto: provider.crypto(),
//!         rand: provider.rand(),
//!     };
//!
//!     group.set_aad(TEST_AAD.to_vec());
//!
//!     // Create commit, stage using modified provider
//!     let err = group
//!         .commit_builder()
//!         // use the normal storage first...
//!         .load_psks(provider.storage())
//!         .unwrap()
//!         .build(provider.rand(), provider.crypto(), &signer, |_proposal| {
//!             true
//!         })
//!         .unwrap()
//!         // ...then switch to error storage
//!         .stage_commit(&test_provider)
//!         .expect_err("expected error");
//!
//!     // The test error should propagate to the builder result
//!     assert_eq!(
//!         err,
//!         CommitBuilderStageError::KeyStoreError(TestStorageError::Injected("writing group state"))
//!     );
//!     // The AAD should not be reset
//!     assert_eq!(group.aad(), TEST_AAD);
//! }
//! ```
//!

use std::{cell::RefCell, collections::HashMap};

use openmls_traits::{storage::CURRENT_VERSION, OpenMlsProvider};

/// Customizable [`OpenMlsProvider`] for use in tests
pub(crate) struct TestProvider<'a, S, R, C>
where
    S: openmls_traits::storage::StorageProvider<CURRENT_VERSION> + 'a,
    R: openmls_traits::random::OpenMlsRand + 'a,
    C: openmls_traits::crypto::OpenMlsCrypto + 'a,
{
    pub(crate) storage: &'a S,
    pub(crate) crypto: &'a C,
    pub(crate) rand: &'a R,
}

impl<'a, S, R, C> OpenMlsProvider for TestProvider<'a, S, R, C>
where
    S: openmls_traits::storage::StorageProvider<CURRENT_VERSION> + 'a,
    R: openmls_traits::random::OpenMlsRand + 'a,
    C: openmls_traits::crypto::OpenMlsCrypto + 'a,
{
    type CryptoProvider = C;
    type RandProvider = R;
    type StorageProvider = S;

    fn storage(&self) -> &Self::StorageProvider {
        self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        self.rand
    }
}

/// Storage provider for use in tests, can be configured to return custom errors on method calls.
pub(crate) struct TestStorageProvider<
    'a,
    D: openmls_traits::storage::StorageProvider<CURRENT_VERSION>,
> {
    pub(crate) delegate: &'a D,

    /// Maps method names to reverse sequence of errors to return
    /// If a method name is not included, delegates to [`Self::delegate`].
    pub(crate) errors: RefCell<
        HashMap<
            &'static str,
            Vec<<Self as openmls_traits::storage::StorageProvider<CURRENT_VERSION>>::Error>,
        >,
    >,
}

/// Custom errors that can wrap the errors of the inner provider or custom strings
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum TestStorageError<D>
where
    D: core::fmt::Debug + std::error::Error,
{
    #[error("Error '{0}' was injected for testing.")]
    Injected(&'static str),
    #[error("An error occurred during delegation: {0}")]
    Delegated(D),
}

impl<'a, D: openmls_traits::storage::StorageProvider<CURRENT_VERSION>> TestStorageProvider<'a, D> {
    fn try_error(&self, function_name: &str) -> Result<(), TestStorageError<D::Error>> {
        match self.errors.borrow_mut().get_mut(function_name) {
            None => Ok(()),
            Some(vec) => match vec.pop() {
                None => Ok(()),
                Some(error) => Err(error),
            },
        }
    }

    fn wrap_result<T>(
        &self,
        result: Result<T, D::Error>,
    ) -> Result<T, <Self as openmls_traits::storage::StorageProvider<CURRENT_VERSION>>::Error> {
        result.map_err(TestStorageError::Delegated)
    }
}

impl<'a, D> openmls_traits::storage::StorageProvider<CURRENT_VERSION> for TestStorageProvider<'a, D>
where
    D: openmls_traits::storage::StorageProvider<CURRENT_VERSION>,
{
    type Error = TestStorageError<D::Error>;

    fn write_mls_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.try_error("write_mls_join_config")?;
        self.wrap_result(self.delegate.write_mls_join_config(group_id, config))
    }

    fn append_own_leaf_node<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        LeafNode: openmls_traits::storage::traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.try_error("append_own_leaf_node")?;
        self.wrap_result(self.delegate.append_own_leaf_node(group_id, leaf_node))
    }

    fn queue_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        self.try_error("queue_proposal")?;
        self.wrap_result(
            self.delegate
                .queue_proposal(group_id, proposal_ref, proposal),
        )
    }

    fn write_tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.try_error("write_tree")?;
        self.wrap_result(self.delegate.write_tree(group_id, tree))
    }

    fn write_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.try_error("write_interim_transcript_hash")?;
        self.wrap_result(
            self.delegate
                .write_interim_transcript_hash(group_id, interim_transcript_hash),
        )
    }

    fn write_context<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.try_error("write_context")?;
        self.wrap_result(self.delegate.write_context(group_id, group_context))
    }

    fn write_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.try_error("write_confirmation_tag")?;
        self.wrap_result(
            self.delegate
                .write_confirmation_tag(group_id, confirmation_tag),
        )
    }

    fn write_group_state<
        GroupState: openmls_traits::storage::traits::GroupState<CURRENT_VERSION>,
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.try_error("write_group_state")?;
        self.wrap_result(self.delegate.write_group_state(group_id, group_state))
    }

    fn write_message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: openmls_traits::storage::traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.try_error("write_message_secrets")?;
        self.wrap_result(
            self.delegate
                .write_message_secrets(group_id, message_secrets),
        )
    }

    fn write_resumption_psk_store<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.try_error("write_resumption_psk_store")?;
        self.wrap_result(
            self.delegate
                .write_resumption_psk_store(group_id, resumption_psk_store),
        )
    }

    fn write_own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.try_error("write_own_leaf_index")?;
        self.wrap_result(self.delegate.write_own_leaf_index(group_id, own_leaf_index))
    }

    fn write_group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.try_error("write_group_epoch_secrets")?;
        self.wrap_result(
            self.delegate
                .write_group_epoch_secrets(group_id, group_epoch_secrets),
        )
    }

    fn write_signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.try_error("write_signature_key_pair")?;
        self.wrap_result(
            self.delegate
                .write_signature_key_pair(public_key, signature_key_pair),
        )
    }

    fn write_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.try_error("write_encryption_key_pair")?;
        self.wrap_result(
            self.delegate
                .write_encryption_key_pair(public_key, key_pair),
        )
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        self.try_error("write_encryption_epoch_key_pairs")?;
        self.wrap_result(
            self.delegate
                .write_encryption_epoch_key_pairs(group_id, epoch, leaf_index, key_pairs),
        )
    }

    fn write_key_package<
        HashReference: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.try_error("write_key_package")?;
        self.wrap_result(self.delegate.write_key_package(hash_ref, key_package))
    }

    fn write_psk<
        PskId: openmls_traits::storage::traits::PskId<CURRENT_VERSION>,
        PskBundle: openmls_traits::storage::traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.try_error("write_psk")?;
        self.wrap_result(self.delegate.write_psk(psk_id, psk))
    }

    fn mls_group_join_config<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.try_error("mls_group_join_config")?;
        self.wrap_result(self.delegate.mls_group_join_config(group_id))
    }

    fn own_leaf_nodes<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        LeafNode: openmls_traits::storage::traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.try_error("own_leaf_nodes")?;
        self.wrap_result(self.delegate.own_leaf_nodes(group_id))
    }

    fn queued_proposal_refs<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.try_error("queued_proposal_refs")?;
        self.wrap_result(self.delegate.queued_proposal_refs(group_id))
    }

    fn queued_proposals<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: openmls_traits::storage::traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        self.try_error("queued_proposals")?;
        self.wrap_result(self.delegate.queued_proposals(group_id))
    }

    fn tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        TreeSync: openmls_traits::storage::traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.try_error("tree")?;
        self.wrap_result(self.delegate.tree(group_id))
    }

    fn group_context<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupContext: openmls_traits::storage::traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.try_error("group_context")?;
        self.wrap_result(self.delegate.group_context(group_id))
    }

    fn interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.try_error("interim_transcript_hash")?;
        self.wrap_result(self.delegate.interim_transcript_hash(group_id))
    }

    fn confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.try_error("confirmation_tag")?;
        self.wrap_result(self.delegate.confirmation_tag(group_id))
    }

    fn group_state<
        GroupState: openmls_traits::storage::traits::GroupState<CURRENT_VERSION>,
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.try_error("group_state")?;
        self.wrap_result(self.delegate.group_state(group_id))
    }

    fn message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: openmls_traits::storage::traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.try_error("message_secrets")?;
        self.wrap_result(self.delegate.message_secrets(group_id))
    }

    fn resumption_psk_store<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.try_error("resumption_psk_store")?;
        self.wrap_result(self.delegate.resumption_psk_store(group_id))
    }

    fn own_leaf_index<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.try_error("own_leaf_index")?;
        self.wrap_result(self.delegate.own_leaf_index(group_id))
    }

    fn group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.try_error("group_epoch_secrets")?;
        self.wrap_result(self.delegate.group_epoch_secrets(group_id))
    }

    fn signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.try_error("signature_key_pair")?;
        self.wrap_result(self.delegate.signature_key_pair(public_key))
    }

    fn encryption_key_pair<
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.try_error("encryption_key_pair")?;
        self.wrap_result(self.delegate.encryption_key_pair(public_key))
    }

    fn encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        self.try_error("encryption_epoch_key_pairs")?;
        self.wrap_result(
            self.delegate
                .encryption_epoch_key_pairs(group_id, epoch, leaf_index),
        )
    }

    fn key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
        KeyPackage: openmls_traits::storage::traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.try_error("key_package")?;
        self.wrap_result(self.delegate.key_package(hash_ref))
    }

    fn psk<
        PskBundle: openmls_traits::storage::traits::PskBundle<CURRENT_VERSION>,
        PskId: openmls_traits::storage::traits::PskId<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.try_error("psk")?;
        self.wrap_result(self.delegate.psk(psk_id))
    }

    fn remove_proposal<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        self.try_error("remove_proposal")?;
        self.wrap_result(self.delegate.remove_proposal(group_id, proposal_ref))
    }

    fn delete_own_leaf_nodes<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_own_leaf_nodes")?;
        self.wrap_result(self.delegate.delete_own_leaf_nodes(group_id))
    }

    fn delete_group_config<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_group_config")?;
        self.wrap_result(self.delegate.delete_group_config(group_id))
    }

    fn delete_tree<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_tree")?;
        self.wrap_result(self.delegate.delete_tree(group_id))
    }

    fn delete_confirmation_tag<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_confirmation_tag")?;
        self.wrap_result(self.delegate.delete_confirmation_tag(group_id))
    }

    fn delete_group_state<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_group_state")?;
        self.wrap_result(self.delegate.delete_group_state(group_id))
    }

    fn delete_context<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_context")?;
        self.wrap_result(self.delegate.delete_context(group_id))
    }

    fn delete_interim_transcript_hash<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_interim_transcript_hash")?;
        self.wrap_result(self.delegate.delete_interim_transcript_hash(group_id))
    }

    fn delete_message_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_message_secrets")?;
        self.wrap_result(self.delegate.delete_message_secrets(group_id))
    }

    fn delete_all_resumption_psk_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_all_resumption_psk_secrets")?;
        self.wrap_result(self.delegate.delete_all_resumption_psk_secrets(group_id))
    }

    fn delete_own_leaf_index<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_own_leaf_index")?;
        self.wrap_result(self.delegate.delete_own_leaf_index(group_id))
    }

    fn delete_group_epoch_secrets<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_group_epoch_secrets")?;
        self.wrap_result(self.delegate.delete_group_epoch_secrets(group_id))
    }

    fn clear_proposal_queue<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("clear_proposal_queue")?;
        self.wrap_result(
            self.delegate
                .clear_proposal_queue::<GroupId, ProposalRef>(group_id),
        )
    }

    fn delete_signature_key_pair<
        SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_signature_key_pair")?;
        self.wrap_result(self.delegate.delete_signature_key_pair(public_key))
    }

    fn delete_encryption_key_pair<
        EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_encryption_key_pair")?;
        self.wrap_result(self.delegate.delete_encryption_key_pair(public_key))
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_encryption_epoch_key_pairs")?;
        self.wrap_result(
            self.delegate
                .delete_encryption_epoch_key_pairs(group_id, epoch, leaf_index),
        )
    }

    fn delete_key_package<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_key_package")?;
        self.wrap_result(self.delegate.delete_key_package(hash_ref))
    }

    fn delete_psk<PskKey: openmls_traits::storage::traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_psk")?;
        self.wrap_result(self.delegate.delete_psk(psk_id))
    }

    #[cfg(feature = "extensions-draft")]
    fn write_application_export_tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: openmls_traits::storage::traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        self.try_error("write_application_export_tree")?;
        self.wrap_result(
            self.delegate
                .write_application_export_tree(group_id, application_export_tree),
        )
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn write_vc_derivation_epoch_state<
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        VcDerivationEpochState: openmls_traits::storage::traits::VcDerivationEpochState<CURRENT_VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
        vc_derivation_epoch_state: &VcDerivationEpochState,
    ) -> Result<(), Self::Error> {
        self.try_error("write_vc_derivation_epoch_state")?;
        self.wrap_result(
            self.delegate
                .write_vc_derivation_epoch_state(epoch_id, vc_derivation_epoch_state),
        )
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn write_vc_operation_tree<
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        VcOperationTree: openmls_traits::storage::traits::VcOperationTree<CURRENT_VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
        vc_operation_tree: &VcOperationTree,
    ) -> Result<(), Self::Error> {
        self.try_error("write_vc_operation_tree")?;
        self.wrap_result(
            self.delegate
                .write_vc_operation_tree(epoch_id, vc_operation_tree),
        )
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn write_retained_key_package_material_batch<
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        VcOperationTree: openmls_traits::storage::traits::VcOperationTree<CURRENT_VERSION>,
        KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
        RetainedKeyPackageMaterial: openmls_traits::storage::traits::RetainedKeyPackageMaterial<CURRENT_VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
        operation_tree: &VcOperationTree,
        materials: &[(KeyPackageRef, RetainedKeyPackageMaterial)],
    ) -> Result<(), Self::Error> {
        self.try_error("write_retained_key_package_material_batch")?;
        self.wrap_result(self.delegate.write_retained_key_package_material_batch(
            epoch_id,
            operation_tree,
            materials,
        ))
    }

    #[cfg(feature = "extensions-draft")]
    fn application_export_tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: openmls_traits::storage::traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        self.try_error("application_export_tree")?;
        self.wrap_result(self.delegate.application_export_tree(group_id))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn vc_derivation_epoch_state<
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        VcDerivationEpochState: openmls_traits::storage::traits::VcDerivationEpochState<CURRENT_VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
    ) -> Result<Option<VcDerivationEpochState>, Self::Error> {
        self.try_error("vc_derivation_epoch_state")?;
        self.wrap_result(self.delegate.vc_derivation_epoch_state(epoch_id))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn vc_operation_tree<
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        VcOperationTree: openmls_traits::storage::traits::VcOperationTree<CURRENT_VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
    ) -> Result<Option<VcOperationTree>, Self::Error> {
        self.try_error("vc_operation_tree")?;
        self.wrap_result(self.delegate.vc_operation_tree(epoch_id))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn retained_key_package_material<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
        RetainedKeyPackageMaterial: openmls_traits::storage::traits::RetainedKeyPackageMaterial<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<RetainedKeyPackageMaterial>, Self::Error> {
        self.try_error("retained_key_package_material")?;
        self.wrap_result(self.delegate.retained_key_package_material(hash_ref))
    }

    #[cfg(feature = "extensions-draft")]
    fn delete_application_export_tree<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: openmls_traits::storage::traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_application_export_tree")?;
        self.wrap_result(
            self.delegate
                .delete_application_export_tree::<GroupId, ApplicationExportTree>(group_id),
        )
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn write_vc_emulation_binding<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        VcEmulationBinding: openmls_traits::storage::traits::VcEmulationBinding<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch: &EpochKey,
        epoch_id: &EpochId,
        binding: &VcEmulationBinding,
    ) -> Result<(), Self::Error> {
        self.try_error("write_vc_emulation_binding")?;
        self.wrap_result(self.delegate.write_vc_emulation_binding(
            group_id,
            group_epoch,
            epoch_id,
            binding,
        ))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn write_vc_derivation_epoch_log_entry<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        VcDerivationEpochLogEntry: openmls_traits::storage::traits::VcDerivationEpochLogEntry<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch_id: &EpochId,
        entry: &VcDerivationEpochLogEntry,
    ) -> Result<(), Self::Error> {
        self.try_error("write_vc_derivation_epoch_log_entry")?;
        self.wrap_result(
            self.delegate
                .write_vc_derivation_epoch_log_entry(group_id, epoch_id, entry),
        )
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn vc_emulation_binding<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
        VcEmulationBinding: openmls_traits::storage::traits::VcEmulationBinding<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch: &EpochKey,
    ) -> Result<Option<VcEmulationBinding>, Self::Error> {
        self.try_error("vc_emulation_binding")?;
        self.wrap_result(self.delegate.vc_emulation_binding(group_id, group_epoch))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn vc_emulation_bindings<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        VcEmulationBinding: openmls_traits::storage::traits::VcEmulationBinding<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<VcEmulationBinding>, Self::Error> {
        self.try_error("vc_emulation_bindings")?;
        self.wrap_result(self.delegate.vc_emulation_bindings(group_id))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn vc_derivation_epoch_log_entries<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        VcDerivationEpochLogEntry: openmls_traits::storage::traits::VcDerivationEpochLogEntry<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<VcDerivationEpochLogEntry>, Self::Error> {
        self.try_error("vc_derivation_epoch_log_entries")?;
        self.wrap_result(self.delegate.vc_derivation_epoch_log_entries(group_id))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn delete_unreferenced_vc_derivation_epoch_states<
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
    >(
        &self,
    ) -> Result<Vec<EpochId>, Self::Error> {
        self.try_error("delete_unreferenced_vc_derivation_epoch_states")?;
        self.wrap_result(
            self.delegate
                .delete_unreferenced_vc_derivation_epoch_states(),
        )
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn delete_vc_emulation_bindings<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epochs: &[EpochKey],
    ) -> Result<(), Self::Error> {
        self.try_error("delete_vc_emulation_bindings")?;
        self.wrap_result(
            self.delegate
                .delete_vc_emulation_bindings(group_id, group_epochs),
        )
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn delete_all_vc_emulation_bindings<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_all_vc_emulation_bindings")?;
        self.wrap_result(self.delegate.delete_all_vc_emulation_bindings(group_id))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn delete_vc_derivation_epoch_log_entries<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch_ids: &[EpochId],
    ) -> Result<(), Self::Error> {
        self.try_error("delete_vc_derivation_epoch_log_entries")?;
        self.wrap_result(
            self.delegate
                .delete_vc_derivation_epoch_log_entries(group_id, epoch_ids),
        )
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn delete_vc_derivation_epoch_log<
        GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_vc_derivation_epoch_log")?;
        self.wrap_result(self.delegate.delete_vc_derivation_epoch_log(group_id))
    }

    #[cfg(feature = "virtual-clients-draft")]
    fn delete_retained_key_package_material<
        KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.try_error("delete_retained_key_package_material")?;
        self.wrap_result(self.delegate.delete_retained_key_package_material(hash_ref))
    }
}
