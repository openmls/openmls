use serde::{de::DeserializeOwned, Serialize};

pub trait GetError: core::fmt::Debug + std::error::Error + PartialEq {
    fn error_kind(&self) -> GetErrorKind;
}

pub trait UpdateError: core::fmt::Debug + std::error::Error + PartialEq {
    fn error_kind(&self) -> UpdateErrorKind;
}

/// The storage version used by OpenMLS
pub const CURRENT_VERSION: u16 = 1;

/// For testing there is a test version defined here.
///
/// THIS VERSION MUST NEVER BE USED OUTSIDE OF TESTS.
#[cfg(feature = "test-utils")]
pub const V_TEST: u16 = u16::MAX;

pub trait StorageProvider<const VERSION: u16> {
    // source for errors
    type GetError: GetError;
    type UpdateError: UpdateError;

    /// Get the version of this provider.
    fn version() -> u16 {
        VERSION
    }

    // Write/queue
    fn queue_proposal(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        proposal_ref: impl ProposalRefEntity<VERSION>,
        proposal: impl QueuedProposalEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_tree(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        tree: impl TreeSyncEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_interim_transcript_hash(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        interim_transcript_hash: impl InterimTranscriptHashEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_context(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        group_context: impl GroupContextEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;
    fn write_confirmation_tag(
        &self,
        group_id: impl GroupIdKey<VERSION>,
        confirmation_tag: impl ConfirmationTagEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    // Write crypto objects

    /// Store a signature key.
    ///
    /// Note that signature keys are defined outside of OpenMLS.
    fn write_signature_key_pair(
        &self,
        public_key: &impl SignaturePublicKeyKey<VERSION>,
        signature_key_pair: &impl SignatureKeyPairEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    /// Store an HPKE init private key.
    ///
    /// This is used for init keys from key packages.
    fn write_init_private_key(
        &self,
        public_key: impl InitKey<VERSION>,
        private_key: impl HpkePrivateKey<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    /// Store an HPKE encryption key pair.
    /// This includes the private and public key
    ///
    /// This is used for encryption keys from leaf nodes.
    fn write_encryption_key_pair(
        &self,
        public_key: impl HpkePublicKey<VERSION>,
        key_pair: impl HpkeKeyPairEntity<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    /// Store key packages.
    ///
    /// Store a key package. This does not include the private keys. They are
    /// stored separately with `write_hpke_private_key`.
    fn write_key_package<TKeyPackage: KeyPackage<VERSION>>(
        &self,
        hash_ref: impl HashReference<VERSION>,
        key_package: TKeyPackage,
    ) -> Result<(), Self::UpdateError>;

    /// Store a PSK.
    ///
    /// This stores PSKs based on the PSK id.
    fn write_psk(
        &self,
        psk_id: impl PskKey<VERSION>,
        psk: impl PskBundle<VERSION>,
    ) -> Result<(), Self::UpdateError>;

    // getter
    fn get_queued_proposal_refs<V: ProposalRefEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<Vec<V>, Self::GetError>;

    fn get_queued_proposals<V: QueuedProposalEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<Vec<V>, Self::GetError>;

    fn get_treesync<V: TreeSyncEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    fn get_group_context<V: GroupContextEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    fn get_interim_transcript_hash<V: InterimTranscriptHashEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    fn get_confirmation_tag<V: ConfirmationTagEntity<VERSION>>(
        &self,
        group_id: &impl GroupIdKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    // Get crypto objects

    /// Get a signature key based on the public key.
    fn signature_key_pair<V: SignatureKeyPairEntity<VERSION>>(
        &self,
        public_key: &impl SignaturePublicKeyKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Get a private init key based on the corresponding public kye.
    fn init_private_key<V: HpkePrivateKey<VERSION>>(
        &self,
        public_key: impl InitKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Get an HPKE encryption key pair based on the public key.
    fn encryption_key_pair<V: HpkeKeyPairEntity<VERSION>>(
        &self,
        public_key: impl HpkePublicKey<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Get a key package based on its hash reference.
    /// TODO: use references for getters
    fn key_package<V: KeyPackage<VERSION>>(
        &self,
        hash_ref: impl HashReference<VERSION>,
    ) -> Result<V, Self::GetError>;

    /// Get a PSK based on the PSK identifier.
    fn psk<V: PskBundle<VERSION>>(&self, psk_id: impl PskKey<VERSION>)
        -> Result<V, Self::GetError>;

    // Delete crypto objects

    /// Delete a signature key pair based on its public key
    fn delete_signature_key_pair<V: SignatureKeyPairEntity<VERSION>>(
        &self,
        public_key: &impl SignaturePublicKeyKey<VERSION>,
    ) -> Result<Option<V>, Self::GetError>;

    /// Delete an HPKE private init key.
    ///
    /// XXX: This should be called when deleting key packages.
    fn delete_init_private_key<V: HpkePrivateKey<VERSION>>(
        &self,
        public_key: impl InitKey<VERSION>,
    ) -> Result<Option<V>, Self::GetError>;

    /// Delete an encryption key pair for a public key.
    fn delete_encryption_key_pair<V: HpkeKeyPairEntity<VERSION>>(
        &self,
        public_key: impl HpkePublicKey<VERSION>,
    ) -> Result<Option<V>, Self::GetError>;

    /// Delete a key package based on the hash reference.
    ///
    /// XXX: This needs to delete all corresponding keys.
    fn delete_key_package<V: KeyPackage<VERSION>>(
        &self,
        hash_ref: impl HashReference<VERSION>,
    ) -> Result<Option<V>, Self::GetError>;

    /// Delete a PSK based on an identifier.
    fn delete_psk<V: PskBundle<VERSION>>(
        &self,
        psk_id: impl PskKey<VERSION>,
    ) -> Result<Option<V>, Self::GetError>;

    /// Returns the MlsGroupState for group with given id.
    fn group_state<GroupState: GroupStateEntity<VERSION>, GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupState, Self::UpdateError>;

    /// Writes the MlsGroupState for group with given id.
    fn write_group_state<GroupState: GroupStateEntity<VERSION>, GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::UpdateError>;

    /// Deletes the MlsGroupState for group with given id.
    fn delete_group_state<GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError>;

    /// Returns the MessageSecretsStore for the group with the given id.
    fn message_secrets<
        GroupId: GroupIdKey<VERSION>,
        MessageSecrets: MessageSecretsEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<MessageSecrets, Self::GetError>;

    /// Writes the MessageSecretsStore for the group with the given id.
    fn write_message_secrets<
        GroupId: GroupIdKey<VERSION>,
        MessageSecrets: MessageSecretsEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::UpdateError>;

    /// Deletes the MessageSecretsStore for the group with the given id.
    fn delete_message_secrets<GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError>;

    /// Returns the ResumptionPskStore for the group with the given id.
    fn resumption_psk_store<
        GroupId: GroupIdKey<VERSION>,
        ResumptionPskStore: ResumptionPskStoreEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<ResumptionPskStore, Self::GetError>;

    /// Writes the ResumptionPskStore for the group with the given id.
    fn write_resumption_psk_store<
        GroupId: GroupIdKey<VERSION>,
        ResumptionPskStore: ResumptionPskStoreEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::UpdateError>;

    /// Deletes the ResumptionPskStore for the group with the given id.
    fn delete_all_resumption_psk_secrets<GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError>;

    /// Returns the own leaf index inside the group for the group with the given id.
    fn own_leaf_index<GroupId: GroupIdKey<VERSION>, LeafNodeIndex: LeafNodeIndexEntity<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<LeafNodeIndex, Self::GetError>;

    /// Writes the own leaf index inside the group for the group with the given id.
    fn write_own_leaf_index<
        GroupId: GroupIdKey<VERSION>,
        LeafNodeIndex: LeafNodeIndexEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::UpdateError>;

    /// Deletes the own leaf index inside the group for the group with the given id.
    fn delete_own_leaf_index<GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError>;

    /// Returns whether to use the RatchetTreeExtension for the group with the given id.
    fn use_ratchet_tree_extension<GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<bool, Self::GetError>;

    /// Sets whether to use the RatchetTreeExtension for the group with the given id.
    fn set_use_ratchet_tree_extension<GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
        value: bool,
    ) -> Result<(), Self::UpdateError>;

    /// Deletes any preference about whether to use the RatchetTreeExtension for the group with the given id.
    fn delete_use_ratchet_tree_extension<GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError>;

    /// Returns the GroupEpochSecrets for the group with the given id.
    fn group_epoch_secrets<
        GroupId: GroupIdKey<VERSION>,
        GroupEpochSecrets: GroupEpochSecretsEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<GroupEpochSecrets, Self::GetError>;

    /// Writes the GroupEpochSecrets for the group with the given id.
    fn write_group_epoch_secrets<
        GroupId: GroupIdKey<VERSION>,
        GroupEpochSecrets: GroupEpochSecretsEntity<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::UpdateError>;

    /// Deletes the GroupEpochSecrets for the group with the given id.
    fn delete_group_epoch_secrets<GroupId: GroupIdKey<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::UpdateError>;
}

// base traits for keys and values
pub trait Key<const VERSION: u16>: Serialize {}
pub trait Entity<const VERSION: u16>: Serialize + DeserializeOwned {}

// in the following we define specific traits for Keys and Entities. That way
// we can don't sacrifice type safety in the implementations of the storage provider.
// note that there are types that are used both as keys and as entities.

// traits for keys, one per data type
pub trait GroupIdKey<const VERSION: u16>: Key<VERSION> {}
pub trait ProposalRefKey<const VERSION: u16>: Key<VERSION> {}
pub trait SignaturePublicKeyKey<const VERSION: u16>: Key<VERSION> {}
pub trait InitKey<const VERSION: u16>: Key<VERSION> {}
pub trait HashReference<const VERSION: u16>: Key<VERSION> {}
pub trait PskKey<const VERSION: u16>: Key<VERSION> {}
pub trait HpkePublicKey<const VERSION: u16>: Key<VERSION> {}

// traits for entity, one per type
pub trait QueuedProposalEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait ProposalRefEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait TreeSyncEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait GroupContextEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait InterimTranscriptHashEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait ConfirmationTagEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait SignatureKeyPairEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait HpkePrivateKey<const VERSION: u16>: Entity<VERSION> {}
pub trait KeyPackage<const VERSION: u16>: Entity<VERSION> {}
pub trait PskBundle<const VERSION: u16>: Entity<VERSION> {}
pub trait HpkeKeyPairEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait GroupStateEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait GroupEpochSecretsEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait LeafNodeIndexEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait GroupUseRatchetTreeExtensionEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait MessageSecretsEntity<const VERSION: u16>: Entity<VERSION> {}
pub trait ResumptionPskStoreEntity<const VERSION: u16>: Entity<VERSION> {}

/// A trait to convert one entity into another one.
///
/// This is implemented for all entities with different versions.
///
/// XXX: I'd like something like this. But this obviously doesn't work. How should this work?
pub trait EntityConversion<const OLD_VERSION: u16, const NEW_VERSION: u16> {
    fn from(old: impl Entity<OLD_VERSION>) -> Self;
}

// errors
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum GetErrorKind {
    NotFound,
    Encoding,
    Internal,
    LockPoisoned,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UpdateErrorKind {
    Encoding,
    Internal,
    LockPoisoned,
    AlreadyExists,
}
