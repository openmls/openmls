//! This module describes the storage provider and type traits.
//! The concept is that the type traits are implemented by OpenMLS, and the storage provider
//! implements the [`StorageProvider`] trait. The trait mostly defines getters and setters, but
//! also a few methods that append to lists (which behave similar to setters).

use serde::{de::DeserializeOwned, Serialize};
/// The storage version used by OpenMLS
pub const CURRENT_VERSION: u16 = 1;

/// For testing there is a test version defined here.
///
/// THIS VERSION MUST NEVER BE USED OUTSIDE OF TESTS.
#[cfg(any(test, feature = "test-utils"))]
pub const V_TEST: u16 = u16::MAX;

/// StorageProvider describes the storage backing OpenMLS and persists the state of OpenMLS groups.
///
/// The getters for individual values usually return a `Result<Option<T>, E>`, where `Err(_)`
/// indicates that some sort of IO or internal error occurred, and `Ok(None)` indicates that no
/// error occurred, but no value exists.
/// Many getters for lists return a `Result<Vec<T>, E>`. In this case, if there was no error but
/// the value doesn't exist, an empty vector should be returned.
///
/// Any value that uses the group id as key is required by the group.
/// Returning `None` or an error for any of them will cause a failure when
/// loading a group.
///
/// More details can be taken from the comments on the respective method.
pub trait StorageProvider<const VERSION: u16> {
    /// An opaque error returned by all methods on this trait.
    type Error: core::fmt::Debug + std::error::Error;

    /// Get the version of this provider.
    fn version() -> u16 {
        VERSION
    }

    //
    //    ---   setters/writers/enqueuers for group state  ---
    //

    /// Writes the MlsGroupJoinConfig for the group with given id to storage
    fn write_mls_join_config<
        GroupId: traits::GroupId<VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error>;

    /// Adds an own leaf node for the group with given id to storage
    fn append_own_leaf_node<
        GroupId: traits::GroupId<VERSION>,
        LeafNode: traits::LeafNode<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error>;

    /// Enqueue a proposal.
    ///
    /// A good way to implement this could be to add a proposal to a proposal store, indexed by the
    /// proposal reference, and adding the reference to a per-group proposal queue list.
    fn queue_proposal<
        GroupId: traits::GroupId<VERSION>,
        ProposalRef: traits::ProposalRef<VERSION>,
        QueuedProposal: traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error>;

    /// Write the TreeSync tree.
    fn write_tree<GroupId: traits::GroupId<VERSION>, TreeSync: traits::TreeSync<VERSION>>(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error>;

    /// Write the interim transcript hash.
    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error>;

    /// Write the group context.
    fn write_context<
        GroupId: traits::GroupId<VERSION>,
        GroupContext: traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error>;

    /// Write the confirmation tag.
    fn write_confirmation_tag<
        GroupId: traits::GroupId<VERSION>,
        ConfirmationTag: traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error>;

    /// Writes the MlsGroupState for group with given id.
    fn write_group_state<
        GroupState: traits::GroupState<VERSION>,
        GroupId: traits::GroupId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error>;

    /// Writes the MessageSecretsStore for the group with the given id.
    fn write_message_secrets<
        GroupId: traits::GroupId<VERSION>,
        MessageSecrets: traits::MessageSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error>;

    /// Writes the ResumptionPskStore for the group with the given id.
    fn write_resumption_psk_store<
        GroupId: traits::GroupId<VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error>;

    /// Writes the own leaf index inside the group for the group with the given id.
    fn write_own_leaf_index<
        GroupId: traits::GroupId<VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error>;

    /// Writes the GroupEpochSecrets for the group with the given id.
    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error>;

    /// Write the ApplicationExportTree for the group with the given id.
    #[cfg(feature = "extensions-draft")]
    fn write_application_export_tree<
        GroupId: traits::GroupId<VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error>;

    /// Write the virtual clients per-derivation-epoch state (the AEAD key
    /// plus the registering client's emulation-group leaf index) for the
    /// given epoch.
    #[cfg(feature = "virtual-clients-draft")]
    fn write_vc_derivation_epoch_state<
        EpochId: traits::VcEpochId<VERSION>,
        VcDerivationEpochState: traits::VcDerivationEpochState<VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
        vc_derivation_epoch_state: &VcDerivationEpochState,
    ) -> Result<(), Self::Error>;

    /// Store the binding of one epoch of a higher-level group to the
    /// derivation epoch whose virtual-client LeafNode was active at that
    /// epoch, keyed by `(group_id, group_epoch)`.
    ///
    /// `epoch_id` duplicates the derivation epoch named inside the opaque
    /// `binding` so that an implementation, which cannot look into the blob,
    /// can answer whether any binding row still names a given epoch (see
    /// [`Self::delete_unreferenced_vc_derivation_epoch_states`]).
    #[cfg(feature = "virtual-clients-draft")]
    fn write_vc_emulation_binding<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
        EpochId: traits::VcEpochId<VERSION>,
        VcEmulationBinding: traits::VcEmulationBinding<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch: &EpochKey,
        epoch_id: &EpochId,
        binding: &VcEmulationBinding,
    ) -> Result<(), Self::Error>;

    /// Store one entry of the log of derivation epochs an emulation group
    /// registered, keyed by `(group_id, epoch_id)`.
    #[cfg(feature = "virtual-clients-draft")]
    fn write_vc_derivation_epoch_log_entry<
        GroupId: traits::GroupId<VERSION>,
        EpochId: traits::VcEpochId<VERSION>,
        VcDerivationEpochLogEntry: traits::VcDerivationEpochLogEntry<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch_id: &EpochId,
        entry: &VcDerivationEpochLogEntry,
    ) -> Result<(), Self::Error>;

    /// Write the per-derivation-epoch Virtual Client Operation Secret Tree
    /// (the lazily derived node secrets plus the per-leaf operation
    /// ratchets) for the given epoch. The tree is written back after every
    /// ratchet advance. It is stored separately from the static
    /// `VcDerivationEpochState` so that per-operation writes do not rewrite
    /// the static fields.
    #[cfg(feature = "virtual-clients-draft")]
    fn write_vc_operation_tree<
        EpochId: traits::VcEpochId<VERSION>,
        VcOperationTree: traits::VcOperationTree<VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
        vc_operation_tree: &VcOperationTree,
    ) -> Result<(), Self::Error>;

    /// Store the advanced operation secret tree for `epoch_id` together with
    /// the retained virtual clients KeyPackage material for every reference in
    /// `materials`.
    ///
    /// A sibling calls this once when it processes a `KeyPackageUpload`: the
    /// upload consumes one operation generation in the tree and produces one
    /// [`RetainedKeyPackageMaterial`](traits::RetainedKeyPackageMaterial) per
    /// KeyPackage. These writes belong together: the tree must never be
    /// persisted as advanced without the materials it produced. Providers do
    /// not open their own transaction, so an application using a transactional
    /// provider (such as SQLite) should call this within a transaction to get
    /// atomicity and rollback on error. The in-memory provider applies the
    /// writes while holding its write lock. Each material is keyed by its
    /// [`HashReference`](traits::HashReference)
    /// and tagged with `epoch_id` so the sweep
    /// ([`Self::delete_unreferenced_vc_derivation_epoch_states`]) can find it.
    /// A subsequent write for the same reference replaces the stored material.
    #[cfg(feature = "virtual-clients-draft")]
    fn write_retained_key_package_material_batch<
        EpochId: traits::VcEpochId<VERSION>,
        VcOperationTree: traits::VcOperationTree<VERSION>,
        KeyPackageRef: traits::HashReference<VERSION>,
        RetainedKeyPackageMaterial: traits::RetainedKeyPackageMaterial<VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
        operation_tree: &VcOperationTree,
        materials: &[(KeyPackageRef, RetainedKeyPackageMaterial)],
    ) -> Result<(), Self::Error>;

    //
    //    ---   setters/writers/enqueuers for crypto objects  ---
    //

    /// Store a signature key.
    ///
    /// The signature key pair is not known to OpenMLS. This may be used by the
    /// application
    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error>;

    /// Store an HPKE encryption key pair.
    /// This includes the private and public key
    ///
    /// This is only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error>;

    /// Store a list of HPKE encryption key pairs for a given epoch.
    /// This includes the private and public keys.
    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error>;

    /// Store key packages.
    ///
    /// Store a key package. This includes the private init key.
    /// The encryption key is stored separately with `write_encryption_key_pair`.
    ///
    /// Note that it is recommended to store a list of the hash references as well
    /// in order to iterate over key packages. OpenMLS does not have a reference
    /// for them.
    // ANCHOR: write_key_package
    fn write_key_package<
        HashReference: traits::HashReference<VERSION>,
        KeyPackage: traits::KeyPackage<VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error>;
    // ANCHOR_END: write_key_package

    /// Store a PSK.
    ///
    /// This stores PSKs based on the PSK id.
    ///
    /// PSKs are only read by OpenMLS. The application is responsible for managing
    /// and storing PSKs.
    fn write_psk<PskId: traits::PskId<VERSION>, PskBundle: traits::PskBundle<VERSION>>(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error>;

    //
    //    ---   getters for group state  ---
    //

    /// Returns the MlsGroupJoinConfig for the group with given id
    fn mls_group_join_config<
        GroupId: traits::GroupId<VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error>;

    // ANCHOR: own_leaf_nodes
    /// Returns the own leaf nodes for the group with given id
    fn own_leaf_nodes<GroupId: traits::GroupId<VERSION>, LeafNode: traits::LeafNode<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error>;
    // ANCHOR_END: own_leaf_nodes

    /// Returns references of all queued proposals for the group with group id `group_id`, or an empty vector of none are stored.
    fn queued_proposal_refs<
        GroupId: traits::GroupId<VERSION>,
        ProposalRef: traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error>;

    /// Returns all queued proposals for the group with group id `group_id`, or an empty vector of none are stored.
    fn queued_proposals<
        GroupId: traits::GroupId<VERSION>,
        ProposalRef: traits::ProposalRef<VERSION>,
        QueuedProposal: traits::QueuedProposal<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error>;

    /// Returns the TreeSync tree for the group with group id `group_id`.
    fn tree<GroupId: traits::GroupId<VERSION>, TreeSync: traits::TreeSync<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error>;

    /// Returns the group context for the group with group id `group_id`.
    fn group_context<
        GroupId: traits::GroupId<VERSION>,
        GroupContext: traits::GroupContext<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error>;

    /// Returns the interim transcript hash for the group with group id `group_id`.
    fn interim_transcript_hash<
        GroupId: traits::GroupId<VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error>;

    /// Returns the confirmation tag for the group with group id `group_id`.
    fn confirmation_tag<
        GroupId: traits::GroupId<VERSION>,
        ConfirmationTag: traits::ConfirmationTag<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error>;

    /// Returns the group state for the group with group id `group_id`.
    fn group_state<GroupState: traits::GroupState<VERSION>, GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error>;

    /// Returns the MessageSecretsStore for the group with the given id.
    fn message_secrets<
        GroupId: traits::GroupId<VERSION>,
        MessageSecrets: traits::MessageSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error>;

    /// Returns the ResumptionPskStore for the group with the given id.
    ///
    /// Returning `None` here is considered an error because the store is needed
    /// by OpenMLS when loading a group.
    fn resumption_psk_store<
        GroupId: traits::GroupId<VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error>;

    /// Returns the own leaf index inside the group for the group with the given id.
    fn own_leaf_index<
        GroupId: traits::GroupId<VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error>;

    /// Returns the GroupEpochSecrets for the group with the given id.
    fn group_epoch_secrets<
        GroupId: traits::GroupId<VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error>;

    //
    //    ---   getter for crypto objects  ---
    //

    /// Get a signature key based on the public key.
    ///
    /// The signature key pair is not known to OpenMLS. This may be used by the
    /// application
    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error>;

    /// Get an HPKE encryption key pair based on the public key.
    ///
    /// This is only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<VERSION>,
        EncryptionKey: traits::EncryptionKey<VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error>;

    /// Get a list of HPKE encryption key pairs for a given epoch.
    /// This includes the private and public keys.
    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error>;

    /// Get a key package based on its hash reference.
    fn key_package<
        KeyPackageRef: traits::HashReference<VERSION>,
        KeyPackage: traits::KeyPackage<VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error>;

    /// Get a PSK based on the PSK identifier.
    fn psk<PskBundle: traits::PskBundle<VERSION>, PskId: traits::PskId<VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error>;

    #[cfg(feature = "extensions-draft")]
    /// Get the application export tree for the group with the given id.
    fn application_export_tree<
        GroupId: traits::GroupId<VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error>;

    #[cfg(feature = "virtual-clients-draft")]
    /// Get the virtual clients per-derivation-epoch state for the given
    /// epoch (the AEAD key plus the registering client's
    /// emulation-group leaf index).
    fn vc_derivation_epoch_state<
        EpochId: traits::VcEpochId<VERSION>,
        VcDerivationEpochState: traits::VcDerivationEpochState<VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
    ) -> Result<Option<VcDerivationEpochState>, Self::Error>;

    /// Load the emulation binding stored for `(group_id, group_epoch)`, if
    /// any (see [`Self::write_vc_emulation_binding`]). This is the hot lookup
    /// of the message protection paths, so implementations should serve it as
    /// a point read.
    #[cfg(feature = "virtual-clients-draft")]
    fn vc_emulation_binding<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
        VcEmulationBinding: traits::VcEmulationBinding<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch: &EpochKey,
    ) -> Result<Option<VcEmulationBinding>, Self::Error>;

    /// Load all emulation bindings of a higher-level group, in unspecified
    /// order (see [`Self::write_vc_emulation_binding`]). Returns an empty
    /// vector if no VC commit has been merged on this group.
    #[cfg(feature = "virtual-clients-draft")]
    fn vc_emulation_bindings<
        GroupId: traits::GroupId<VERSION>,
        VcEmulationBinding: traits::VcEmulationBinding<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<VcEmulationBinding>, Self::Error>;

    /// Load all derivation-epoch log entries of the given emulation group, in
    /// unspecified order (see [`Self::write_vc_derivation_epoch_log_entry`]).
    /// Returns an empty vector if the group never registered a derivation
    /// epoch.
    #[cfg(feature = "virtual-clients-draft")]
    fn vc_derivation_epoch_log_entries<
        GroupId: traits::GroupId<VERSION>,
        VcDerivationEpochLogEntry: traits::VcDerivationEpochLogEntry<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<VcDerivationEpochLogEntry>, Self::Error>;

    /// Get the per-derivation-epoch Virtual Client Operation Secret Tree for
    /// the given epoch (the lazily derived node secrets plus the per-leaf
    /// operation ratchets).
    #[cfg(feature = "virtual-clients-draft")]
    fn vc_operation_tree<
        EpochId: traits::VcEpochId<VERSION>,
        VcOperationTree: traits::VcOperationTree<VERSION>,
    >(
        &self,
        epoch_id: &EpochId,
    ) -> Result<Option<VcOperationTree>, Self::Error>;

    /// Get the retained virtual clients KeyPackage material for the given
    /// KeyPackage reference. Returns `None` if no material was stored for that
    /// reference.
    #[cfg(feature = "virtual-clients-draft")]
    fn retained_key_package_material<
        KeyPackageRef: traits::HashReference<VERSION>,
        RetainedKeyPackageMaterial: traits::RetainedKeyPackageMaterial<VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<RetainedKeyPackageMaterial>, Self::Error>;

    //
    //     ---    deleters for group state    ---
    //

    /// Removes an individual proposal from the proposal queue of the group with the provided id
    fn remove_proposal<
        GroupId: traits::GroupId<VERSION>,
        ProposalRef: traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error>;

    /// Deletes own leaf nodes for the given id from storage
    fn delete_own_leaf_nodes<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the MlsGroupJoinConfig for the given id from storage
    fn delete_group_config<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the tree from storage
    fn delete_tree<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the confirmation tag from storage
    fn delete_confirmation_tag<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the MlsGroupState for group with given id.
    fn delete_group_state<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the group context for the group with given id
    fn delete_context<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the interim transcript hash for the group with given id
    fn delete_interim_transcript_hash<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the MessageSecretsStore for the group with the given id.
    fn delete_message_secrets<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the ResumptionPskStore for the group with the given id.
    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the own leaf index inside the group for the group with the given id.
    fn delete_own_leaf_index<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Deletes the GroupEpochSecrets for the group with the given id.
    fn delete_group_epoch_secrets<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Clear the proposal queue for the group with the given id.
    fn clear_proposal_queue<
        GroupId: traits::GroupId<VERSION>,
        ProposalRef: traits::ProposalRef<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    //
    //    ---   deleters for crypto objects   ---
    //

    /// Delete a signature key pair based on its public key
    ///
    /// The signature key pair is not known to OpenMLS. This may be used by the
    /// application
    fn delete_signature_key_pair<SignaturePublicKey: traits::SignaturePublicKey<VERSION>>(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error>;

    /// Delete an encryption key pair for a public key.
    ///
    /// This is only be used for encryption key pairs that are generated for
    /// update leaf nodes. All other encryption key pairs are stored as part
    /// of the key package or the epoch encryption key pairs.
    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error>;

    /// Delete a list of HPKE encryption key pairs for a given epoch.
    /// This includes the private and public keys.
    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error>;

    /// Delete a key package based on the hash reference.
    ///
    /// Under the `virtual-clients-draft` feature, an implementation must also
    /// delete the retained virtual clients KeyPackage material stored for the
    /// same reference (see `delete_retained_key_package_material`, which only
    /// exists under that feature).
    /// Deleting non-existent material is a no-op, so this is safe for
    /// KeyPackages that were never uploaded by a virtual client.
    fn delete_key_package<KeyPackageRef: traits::HashReference<VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error>;

    /// Delete a PSK based on an identifier.
    fn delete_psk<PskKey: traits::PskId<VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error>;

    /// Delete the application export tree for the group with the given id.
    #[cfg(feature = "extensions-draft")]
    fn delete_application_export_tree<
        GroupId: traits::GroupId<VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Delete the per-epoch state and operation tree of every derivation
    /// epoch that nothing references anymore, and return the ids of the
    /// deleted epochs.
    ///
    /// Every epoch with a stored state
    /// ([`Self::write_vc_derivation_epoch_state`]) or operation tree
    /// ([`Self::write_vc_operation_tree`]) is a candidate. A candidate is
    /// referenced, and must be kept, if any of three sources names its
    /// `epoch_id`: a derivation-epoch log entry
    /// ([`Self::write_vc_derivation_epoch_log_entry`]), an emulation binding
    /// ([`Self::write_vc_emulation_binding`]), or retained KeyPackage material
    /// ([`Self::write_retained_key_package_material_batch`]).
    ///
    /// The reference checks and the deletions must apply atomically, or a
    /// reference stored concurrently can be orphaned. Providers do not open
    /// their own transaction, so an application using a transactional
    /// provider should call this within one.
    #[cfg(feature = "virtual-clients-draft")]
    fn delete_unreferenced_vc_derivation_epoch_states<EpochId: traits::VcEpochId<VERSION>>(
        &self,
    ) -> Result<Vec<EpochId>, Self::Error>;

    /// Remove the emulation bindings the given group stored under the given
    /// group epochs. Missing rows are skipped.
    #[cfg(feature = "virtual-clients-draft")]
    fn delete_vc_emulation_bindings<
        GroupId: traits::GroupId<VERSION>,
        EpochKey: traits::EpochKey<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epochs: &[EpochKey],
    ) -> Result<(), Self::Error>;

    /// Remove all emulation bindings of the given group.
    #[cfg(feature = "virtual-clients-draft")]
    fn delete_all_vc_emulation_bindings<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Remove the derivation-epoch log entries the given group stored for the
    /// given derivation epochs. Missing rows are skipped.
    #[cfg(feature = "virtual-clients-draft")]
    fn delete_vc_derivation_epoch_log_entries<
        GroupId: traits::GroupId<VERSION>,
        EpochId: traits::VcEpochId<VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch_ids: &[EpochId],
    ) -> Result<(), Self::Error>;

    /// Remove all derivation-epoch log entries of the given group.
    #[cfg(feature = "virtual-clients-draft")]
    fn delete_vc_derivation_epoch_log<GroupId: traits::GroupId<VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error>;

    /// Delete the retained virtual clients KeyPackage material stored for the
    /// given KeyPackage reference. Called from [`Self::delete_key_package`] so
    /// the material is removed together with the KeyPackage it describes, and
    /// by the library once a Welcome join has bound the joined group to the
    /// material's derivation epoch.
    #[cfg(feature = "virtual-clients-draft")]
    fn delete_retained_key_package_material<KeyPackageRef: traits::HashReference<VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error>;
}

// base traits for keys and values

// ANCHOR: key_trait
/// Key is a trait implemented by all types that serve as a key (in the database sense) to in the
/// storage. For example, a GroupId is a key to the stored entities for the group with that id.
/// The point of a key is not to be stored, it's to address something that is stored.
pub trait Key<const VERSION: u16>: Serialize {}
// ANCHOR_END: key_trait

// ANCHOR: entity_trait
/// Entity is a trait implemented by the values being stored.
pub trait Entity<const VERSION: u16>: Serialize + DeserializeOwned {}
// ANCHOR_END: entity_trait

impl Entity<CURRENT_VERSION> for bool {}
impl Entity<CURRENT_VERSION> for u8 {}

// in the following we define specific traits for Keys and Entities. That way
// we can don't sacrifice type safety in the implementations of the storage provider.
// note that there are types that are used both as keys and as entities.

// ANCHOR: traits
/// Each trait in this module corresponds to a type. Some are used as keys, some as
/// entities, and some both. Therefore, the Key and/or Entity traits also need to be implemented.
pub mod traits {
    use super::{Entity, Key};

    // traits for keys, one per data type
    pub trait GroupId<const VERSION: u16>: Key<VERSION> {}
    pub trait SignaturePublicKey<const VERSION: u16>: Key<VERSION> {}
    pub trait HashReference<const VERSION: u16>: Key<VERSION> {}
    pub trait PskId<const VERSION: u16>: Key<VERSION> {}
    pub trait EncryptionKey<const VERSION: u16>: Key<VERSION> {}
    pub trait EpochKey<const VERSION: u16>: Key<VERSION> {}

    // traits for entity, one per type
    pub trait QueuedProposal<const VERSION: u16>: Entity<VERSION> {}
    pub trait TreeSync<const VERSION: u16>: Entity<VERSION> {}
    pub trait GroupContext<const VERSION: u16>: Entity<VERSION> {}
    pub trait InterimTranscriptHash<const VERSION: u16>: Entity<VERSION> {}
    pub trait ConfirmationTag<const VERSION: u16>: Entity<VERSION> {}
    pub trait SignatureKeyPair<const VERSION: u16>: Entity<VERSION> {}
    pub trait PskBundle<const VERSION: u16>: Entity<VERSION> {}
    pub trait HpkeKeyPair<const VERSION: u16>: Entity<VERSION> {}
    pub trait GroupState<const VERSION: u16>: Entity<VERSION> {}
    pub trait GroupEpochSecrets<const VERSION: u16>: Entity<VERSION> {}
    pub trait LeafNodeIndex<const VERSION: u16>: Entity<VERSION> {}
    pub trait MessageSecrets<const VERSION: u16>: Entity<VERSION> {}
    pub trait ResumptionPskStore<const VERSION: u16>: Entity<VERSION> {}
    pub trait KeyPackage<const VERSION: u16>: Entity<VERSION> {}
    pub trait MlsGroupJoinConfig<const VERSION: u16>: Entity<VERSION> {}
    pub trait LeafNode<const VERSION: u16>: Entity<VERSION> {}
    pub trait ApplicationExportTree<const VERSION: u16>: Entity<VERSION> {}
    #[cfg(feature = "virtual-clients-draft")]
    pub trait VcEpochId<const VERSION: u16>: Key<VERSION> + Entity<VERSION> {}
    #[cfg(feature = "virtual-clients-draft")]
    pub trait VcDerivationEpochState<const VERSION: u16>: Entity<VERSION> {}
    #[cfg(feature = "virtual-clients-draft")]
    pub trait VcEmulationBinding<const VERSION: u16>: Entity<VERSION> {}
    #[cfg(feature = "virtual-clients-draft")]
    pub trait VcDerivationEpochLogEntry<const VERSION: u16>: Entity<VERSION> {}
    #[cfg(feature = "virtual-clients-draft")]
    pub trait VcOperationTree<const VERSION: u16>: Entity<VERSION> {}
    #[cfg(feature = "virtual-clients-draft")]
    pub trait RetainedKeyPackageMaterial<const VERSION: u16>: Entity<VERSION> {}

    // traits for types that implement both
    pub trait ProposalRef<const VERSION: u16>: Entity<VERSION> + Key<VERSION> {}
}
// ANCHOR_END: traits

impl<const VERSION: u16> Entity<VERSION> for Vec<u8> {}
