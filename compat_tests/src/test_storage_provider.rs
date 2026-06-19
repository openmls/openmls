#![allow(dead_code, unused)]

use std::sync::{Arc, Mutex};

#[derive(Default)]
pub struct TestStorageProvider {
    data: Arc<Mutex<Option<Vec<u8>>>>,
}

macro_rules! impl_storage_provider_basic {
    () => {
        /// An opaque error returned by all methods on this trait.
        type Error = postcard::Error;

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Adds an own leaf node for the group with given id to storage
        fn append_own_leaf_node<
            GroupId: traits::GroupId<VERSION>,
            LeafNode: traits::LeafNode<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            leaf_node: &LeafNode,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the TreeSync tree.
        fn write_tree<GroupId: traits::GroupId<VERSION>, TreeSync: traits::TreeSync<VERSION>>(
            &self,
            group_id: &GroupId,
            tree: &TreeSync,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the interim transcript hash.
        fn write_interim_transcript_hash<
            GroupId: traits::GroupId<VERSION>,
            InterimTranscriptHash: traits::InterimTranscriptHash<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            interim_transcript_hash: &InterimTranscriptHash,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the group context.
        fn write_context<
            GroupId: traits::GroupId<VERSION>,
            GroupContext: traits::GroupContext<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_context: &GroupContext,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the confirmation tag.
        fn write_confirmation_tag<
            GroupId: traits::GroupId<VERSION>,
            ConfirmationTag: traits::ConfirmationTag<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            confirmation_tag: &ConfirmationTag,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Writes the MlsGroupState for group with given id.
        fn write_group_state<
            GroupState: traits::GroupState<VERSION>,
            GroupId: traits::GroupId<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_state: &GroupState,
        ) -> Result<(), Self::Error> {
            let mut data = self.data.lock().unwrap();
            let group_state = postcard::to_allocvec(group_state)?;
            let _ = data.insert(group_state);

            Ok(())
        }

        /// Writes the MessageSecretsStore for the group with the given id.
        fn write_message_secrets<
            GroupId: traits::GroupId<VERSION>,
            MessageSecrets: traits::MessageSecrets<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            message_secrets: &MessageSecrets,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Writes the ResumptionPskStore for the group with the given id.
        fn write_resumption_psk_store<
            GroupId: traits::GroupId<VERSION>,
            ResumptionPskStore: traits::ResumptionPskStore<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            resumption_psk_store: &ResumptionPskStore,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Writes the own leaf index inside the group for the group with the given id.
        fn write_own_leaf_index<
            GroupId: traits::GroupId<VERSION>,
            LeafNodeIndex: traits::LeafNodeIndex<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            own_leaf_index: &LeafNodeIndex,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Writes the GroupEpochSecrets for the group with the given id.
        fn write_group_epoch_secrets<
            GroupId: traits::GroupId<VERSION>,
            GroupEpochSecrets: traits::GroupEpochSecrets<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_epoch_secrets: &GroupEpochSecrets,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes own leaf nodes for the given id from storage
        fn delete_own_leaf_nodes<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the MlsGroupJoinConfig for the given id from storage
        fn delete_group_config<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the tree from storage
        fn delete_tree<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the confirmation tag from storage
        fn delete_confirmation_tag<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the MlsGroupState for group with given id.
        fn delete_group_state<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the group context for the group with given id
        fn delete_context<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the interim transcript hash for the group with given id
        fn delete_interim_transcript_hash<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the MessageSecretsStore for the group with the given id.
        fn delete_message_secrets<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the ResumptionPskStore for the group with the given id.
        fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the own leaf index inside the group for the group with the given id.
        fn delete_own_leaf_index<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the GroupEpochSecrets for the group with the given id.
        fn delete_group_epoch_secrets<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Clear the proposal queue for the group with the given id.
        fn clear_proposal_queue<
            GroupId: traits::GroupId<VERSION>,
            ProposalRef: traits::ProposalRef<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Delete an encryption key pair for a public key.
        ///
        /// This is only be used for encryption key pairs that are generated for
        /// update leaf nodes. All other encryption key pairs are stored as part
        /// of the key package or the epoch encryption key pairs.
        fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<VERSION>>(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Delete a key package based on the hash reference.
        ///
        /// This function only deletes the key package.
        /// The corresponding encryption keys must be deleted separately.
        fn delete_key_package<KeyPackageRef: traits::HashReference<VERSION>>(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Delete a PSK based on an identifier.
        fn delete_psk<PskKey: traits::PskId<VERSION>>(
            &self,
            psk_id: &PskKey,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }
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
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
            unimplemented!()
        }

        // ANCHOR: own_leaf_nodes
        /// Returns the own leaf nodes for the group with given id
        fn own_leaf_nodes<
            GroupId: traits::GroupId<VERSION>,
            LeafNode: traits::LeafNode<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<LeafNode>, Self::Error> {
            unimplemented!()
        }
        // ANCHOR_END: own_leaf_nodes

        /// Returns references of all queued proposals for the group with group id `group_id`, or an empty vector of none are stored.
        fn queued_proposal_refs<
            GroupId: traits::GroupId<VERSION>,
            ProposalRef: traits::ProposalRef<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<ProposalRef>, Self::Error> {
            unimplemented!()
        }

        /// Returns all queued proposals for the group with group id `group_id`, or an empty vector of none are stored.
        fn queued_proposals<
            GroupId: traits::GroupId<VERSION>,
            ProposalRef: traits::ProposalRef<VERSION>,
            QueuedProposal: traits::QueuedProposal<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
            unimplemented!()
        }

        /// Returns the TreeSync tree for the group with group id `group_id`.
        fn tree<GroupId: traits::GroupId<VERSION>, TreeSync: traits::TreeSync<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<TreeSync>, Self::Error> {
            unimplemented!()
        }

        /// Returns the group context for the group with group id `group_id`.
        fn group_context<
            GroupId: traits::GroupId<VERSION>,
            GroupContext: traits::GroupContext<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupContext>, Self::Error> {
            unimplemented!()
        }

        /// Returns the interim transcript hash for the group with group id `group_id`.
        fn interim_transcript_hash<
            GroupId: traits::GroupId<VERSION>,
            InterimTranscriptHash: traits::InterimTranscriptHash<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
            unimplemented!()
        }

        /// Returns the confirmation tag for the group with group id `group_id`.
        fn confirmation_tag<
            GroupId: traits::GroupId<VERSION>,
            ConfirmationTag: traits::ConfirmationTag<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ConfirmationTag>, Self::Error> {
            unimplemented!()
        }

        /// Returns the group state for the group with group id `group_id`.
        fn group_state<
            GroupState: traits::GroupState<VERSION>,
            GroupId: traits::GroupId<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupState>, Self::Error> {
            let mut data = self.data.lock().unwrap();

            if let Some(data) = data.as_ref() {
                let group_state = postcard::from_bytes::<GroupState>(data)?;

                Ok(Some(group_state))
            } else {
                Ok(None)
            }
        }

        /// Returns the MessageSecretsStore for the group with the given id.
        fn message_secrets<
            GroupId: traits::GroupId<VERSION>,
            MessageSecrets: traits::MessageSecrets<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MessageSecrets>, Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<Option<ResumptionPskStore>, Self::Error> {
            unimplemented!()
        }

        /// Returns the own leaf index inside the group for the group with the given id.
        fn own_leaf_index<
            GroupId: traits::GroupId<VERSION>,
            LeafNodeIndex: traits::LeafNodeIndex<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<LeafNodeIndex>, Self::Error> {
            unimplemented!()
        }

        /// Returns the GroupEpochSecrets for the group with the given id.
        fn group_epoch_secrets<
            GroupId: traits::GroupId<VERSION>,
            GroupEpochSecrets: traits::GroupEpochSecrets<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<Option<SignatureKeyPair>, Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<Option<HpkeKeyPair>, Self::Error> {
            unimplemented!()
        }

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
        ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
            unimplemented!()
        }

        /// Get a key package based on its hash reference.
        fn key_package<
            KeyPackageRef: traits::HashReference<VERSION>,
            KeyPackage: traits::KeyPackage<VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<Option<KeyPackage>, Self::Error> {
            unimplemented!()
        }

        /// Get a PSK based on the PSK identifier.
        fn psk<PskBundle: traits::PskBundle<VERSION>, PskId: traits::PskId<VERSION>>(
            &self,
            psk_id: &PskId,
        ) -> Result<Option<PskBundle>, Self::Error> {
            unimplemented!()
        }
    };
}

macro_rules! impl_storage_provider_feature_flagged {
    () => {
        /// Write the ApplicationExportTree for the group with the given id.
        #[cfg(feature = "extensions-draft-08")]
        fn write_application_export_tree<
            GroupId: traits::GroupId<VERSION>,
            ApplicationExportTree: traits::ApplicationExportTree<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            application_export_tree: &ApplicationExportTree,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the virtual clients per-emulation-epoch state (the AEAD key
        /// plus the registering client's emulation-group leaf index) for the
        /// given epoch.
        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_emulation_epoch_state<
            EpochId: traits::VcEpochId<VERSION>,
            VcEmulationEpochState: traits::VcEmulationEpochState<VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
            vc_emulation_epoch_state: &VcEmulationEpochState,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the virtual clients PPRF for the given epoch.
        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_pprf<EpochId: traits::VcEpochId<VERSION>, VcPprf: traits::VcPprf<VERSION>>(
            &self,
            epoch_id: &EpochId,
            vc_pprf: &VcPprf,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Store the record binding each recent epoch of a higher-level group to
        /// the emulation-group epoch whose virtual-client LeafNode was active at
        /// that epoch. Used by the reuse-guard derivation path to look up the
        /// per-message `ReuseGuardSecret` for the epoch a message was sent in.
        ///
        /// The record is updated on every commit merged on the higher-level
        /// group and prunes its own entries in lockstep with the group's
        /// message-secrets retention. A subsequent write replaces any previously
        /// stored record.
        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_emulation_bindings<
            GroupId: traits::GroupId<VERSION>,
            VcEmulationBindings: traits::VcEmulationBindings<VERSION>,
        >(
            &self,
            group_id: &GroupId,
            bindings: &VcEmulationBindings,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "extensions-draft-08")]
        /// Get the application export tree for the group with the given id.
        fn application_export_tree<
            GroupId: traits::GroupId<VERSION>,
            ApplicationExportTree: traits::ApplicationExportTree<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ApplicationExportTree>, Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        /// Get the virtual clients per-emulation-epoch state for the given
        /// epoch (the AEAD key plus the registering client's
        /// emulation-group leaf index).
        fn vc_emulation_epoch_state<
            EpochId: traits::VcEpochId<VERSION>,
            VcEmulationEpochState: traits::VcEmulationEpochState<VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
        ) -> Result<Option<VcEmulationEpochState>, Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        /// Get the virtual clients PPRF for the given epoch.
        fn vc_pprf<EpochId: traits::VcEpochId<VERSION>, VcPprf: traits::VcPprf<VERSION>>(
            &self,
            epoch_id: &EpochId,
        ) -> Result<Option<VcPprf>, Self::Error> {
            unimplemented!()
        }

        /// Load the per-epoch emulation bindings of a higher-level group (see
        /// [`Self::write_vc_emulation_bindings`]). Returns `None` if no VC
        /// commit has been merged on this higher-level group.
        #[cfg(feature = "virtual-clients-draft")]
        fn vc_emulation_bindings<
            GroupId: traits::GroupId<VERSION>,
            VcEmulationBindings: traits::VcEmulationBindings<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<VcEmulationBindings>, Self::Error> {
            unimplemented!()
        }

        /// Delete the application export tree for the group with the given id.
        #[cfg(feature = "extensions-draft-08")]
        fn delete_application_export_tree<
            GroupId: traits::GroupId<VERSION>,
            ApplicationExportTree: traits::ApplicationExportTree<VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Delete the emulation-epoch state stored under the given epoch id.
        ///
        /// Never called by OpenMLS: the state is keyed by emulation epoch and
        /// may be referenced by several higher-level groups, so the
        /// application must call this once the emulation epoch is no longer
        /// referenced by any group.
        #[cfg(feature = "virtual-clients-draft")]
        fn delete_vc_emulation_epoch_state<EpochId: traits::VcEpochId<VERSION>>(
            &self,
            epoch_id: &EpochId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Delete the virtual-clients PPRF stored under the given epoch id.
        ///
        /// Never called by OpenMLS: like the emulation-epoch state, the PPRF
        /// is keyed by emulation epoch and may be referenced by several
        /// higher-level groups, so the application must call this once the
        /// emulation epoch is no longer referenced by any group.
        #[cfg(feature = "virtual-clients-draft")]
        fn delete_vc_pprf<EpochId: traits::VcEpochId<VERSION>>(
            &self,
            epoch_id: &EpochId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Remove the per-epoch emulation bindings of the given group. Called
        /// when the group is being deleted.
        #[cfg(feature = "virtual-clients-draft")]
        fn delete_vc_emulation_bindings<GroupId: traits::GroupId<VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }
    };
}

use openmls_traits::storage::CURRENT_VERSION as VERSION;

mod current {
    use super::*;
    use openmls_traits::storage::{traits, StorageProvider};

    impl StorageProvider<VERSION> for TestStorageProvider {
        impl_storage_provider_basic!();
        impl_storage_provider_feature_flagged!();
    }
}

mod compat {
    use super::*;
    use openmls_traits_0_4_1::storage::{traits, StorageProvider};

    impl StorageProvider<VERSION> for TestStorageProvider {
        impl_storage_provider_basic!();
    }
}
