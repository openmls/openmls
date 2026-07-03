#![allow(dead_code, unused)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Default)]
struct Data {
    message_secrets: HashMap<Vec<u8>, Vec<u8>>,
    group_state: HashMap<Vec<u8>, Vec<u8>>,
}

#[derive(Default)]
pub struct TestStorageProvider(Arc<Mutex<Data>>);

macro_rules! impl_storage_provider_basic {
    () => {
        /// An opaque error returned by all methods on this trait.
        type Error = postcard::Error;

        //
        //    ---   setters/writers/enqueuers for group state  ---
        //

        /// Writes the MlsGroupJoinConfig for the group with given id to storage
        fn write_mls_join_config<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            config: &MlsGroupJoinConfig,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Adds an own leaf node for the group with given id to storage
        fn append_own_leaf_node<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNode: traits::LeafNode<CURRENT_VERSION>,
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
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
            QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            proposal_ref: &ProposalRef,
            proposal: &QueuedProposal,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the TreeSync tree.
        fn write_tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            TreeSync: traits::TreeSync<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            tree: &TreeSync,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the interim transcript hash.
        fn write_interim_transcript_hash<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            interim_transcript_hash: &InterimTranscriptHash,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the group context.
        fn write_context<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupContext: traits::GroupContext<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_context: &GroupContext,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Write the confirmation tag.
        fn write_confirmation_tag<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            confirmation_tag: &ConfirmationTag,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Writes the MlsGroupState for group with given id.
        fn write_group_state<
            GroupState: traits::GroupState<CURRENT_VERSION>,
            GroupId: traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_state: &GroupState,
        ) -> Result<(), Self::Error> {
            let mut data = self.0.lock().unwrap();
            let group_id = postcard::to_allocvec(group_id)?;
            let group_state = postcard::to_allocvec(group_state)?;
            let _ = data.group_state.insert(group_id, group_state);

            Ok(())
        }

        /// Writes the MessageSecretsStore for the group with the given id.
        fn write_message_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            message_secrets: &MessageSecrets,
        ) -> Result<(), Self::Error> {
            let mut data = self.0.lock().unwrap();
            let group_id = postcard::to_allocvec(group_id)?;
            let message_secrets = postcard::to_allocvec(message_secrets)?;
            let _ = data.message_secrets.insert(group_id, message_secrets);

            Ok(())
        }

        /// Writes the ResumptionPskStore for the group with the given id.
        fn write_resumption_psk_store<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            resumption_psk_store: &ResumptionPskStore,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Writes the own leaf index inside the group for the group with the given id.
        fn write_own_leaf_index<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            own_leaf_index: &LeafNodeIndex,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Writes the GroupEpochSecrets for the group with the given id.
        fn write_group_epoch_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
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
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            proposal_ref: &ProposalRef,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes own leaf nodes for the given id from storage
        fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the MlsGroupJoinConfig for the given id from storage
        fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the tree from storage
        fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the confirmation tag from storage
        fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the MlsGroupState for group with given id.
        fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the group context for the group with given id
        fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the interim transcript hash for the group with given id
        fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the MessageSecretsStore for the group with the given id.
        fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the ResumptionPskStore for the group with the given id.
        fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the own leaf index inside the group for the group with the given id.
        fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Deletes the GroupEpochSecrets for the group with the given id.
        fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Clear the proposal queue for the group with the given id.
        fn clear_proposal_queue<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
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
        fn delete_signature_key_pair<
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        >(
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
        fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Delete a list of HPKE encryption key pairs for a given epoch.
        /// This includes the private and public keys.
        fn delete_encryption_epoch_key_pairs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            EpochKey: traits::EpochKey<CURRENT_VERSION>,
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
        fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        /// Delete a PSK based on an identifier.
        fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
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
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
            SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
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
            EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
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
            HashReference: traits::HashReference<CURRENT_VERSION>,
            KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
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
        fn write_psk<
            PskId: traits::PskId<CURRENT_VERSION>,
            PskBundle: traits::PskBundle<CURRENT_VERSION>,
        >(
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
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
            unimplemented!()
        }

        // ANCHOR: own_leaf_nodes
        /// Returns the own leaf nodes for the group with given id
        fn own_leaf_nodes<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNode: traits::LeafNode<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<LeafNode>, Self::Error> {
            unimplemented!()
        }
        // ANCHOR_END: own_leaf_nodes

        /// Returns references of all queued proposals for the group with group id `group_id`, or an empty vector of none are stored.
        fn queued_proposal_refs<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<ProposalRef>, Self::Error> {
            unimplemented!()
        }

        /// Returns all queued proposals for the group with group id `group_id`, or an empty vector of none are stored.
        fn queued_proposals<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
            QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
            unimplemented!()
        }

        /// Returns the TreeSync tree for the group with group id `group_id`.
        fn tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            TreeSync: traits::TreeSync<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<TreeSync>, Self::Error> {
            unimplemented!()
        }

        /// Returns the group context for the group with group id `group_id`.
        fn group_context<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupContext: traits::GroupContext<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupContext>, Self::Error> {
            unimplemented!()
        }

        /// Returns the interim transcript hash for the group with group id `group_id`.
        fn interim_transcript_hash<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
            unimplemented!()
        }

        /// Returns the confirmation tag for the group with group id `group_id`.
        fn confirmation_tag<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ConfirmationTag>, Self::Error> {
            unimplemented!()
        }

        /// Returns the group state for the group with group id `group_id`.
        fn group_state<
            GroupState: traits::GroupState<CURRENT_VERSION>,
            GroupId: traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupState>, Self::Error> {
            let mut data = self.0.lock().unwrap();

            let group_id = postcard::to_allocvec(group_id)?;

            if let Some(data) = data.group_state.get(&group_id) {
                let group_state = postcard::from_bytes::<GroupState>(data)?;

                Ok(Some(group_state))
            } else {
                Ok(None)
            }
        }

        /// Returns the MessageSecretsStore for the group with the given id.
        fn message_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MessageSecrets>, Self::Error> {
            let mut data = self.0.lock().unwrap();

            let group_id = postcard::to_allocvec(group_id)?;

            if let Some(data) = data.message_secrets.get(&group_id) {
                let message_secrets = postcard::from_bytes::<MessageSecrets>(data)?;

                Ok(Some(message_secrets))
            } else {
                Ok(None)
            }
        }

        /// Returns the ResumptionPskStore for the group with the given id.
        ///
        /// Returning `None` here is considered an error because the store is needed
        /// by OpenMLS when loading a group.
        fn resumption_psk_store<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ResumptionPskStore>, Self::Error> {
            unimplemented!()
        }

        /// Returns the own leaf index inside the group for the group with the given id.
        fn own_leaf_index<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<LeafNodeIndex>, Self::Error> {
            unimplemented!()
        }

        /// Returns the GroupEpochSecrets for the group with the given id.
        fn group_epoch_secrets<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
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
            SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
            SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
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
            HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
            EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        >(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<Option<HpkeKeyPair>, Self::Error> {
            unimplemented!()
        }

        /// Get a list of HPKE encryption key pairs for a given epoch.
        /// This includes the private and public keys.
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
            unimplemented!()
        }

        /// Get a key package based on its hash reference.
        fn key_package<
            KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
            KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<Option<KeyPackage>, Self::Error> {
            unimplemented!()
        }

        /// Get a PSK based on the PSK identifier.
        fn psk<
            PskBundle: traits::PskBundle<CURRENT_VERSION>,
            PskId: traits::PskId<CURRENT_VERSION>,
        >(
            &self,
            psk_id: &PskId,
        ) -> Result<Option<PskBundle>, Self::Error> {
            unimplemented!()
        }
    };
}

macro_rules! impl_storage_provider_extensions_draft {
    () => {
        /// Write the ApplicationExportTree for the group with the given id.
        #[cfg(feature = "extensions-draft")]
        fn write_application_export_tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            application_export_tree: &ApplicationExportTree,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }
        #[cfg(feature = "extensions-draft")]
        /// Get the application export tree for the group with the given id.
        fn application_export_tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ApplicationExportTree>, Self::Error> {
            unimplemented!()
        }

        /// Delete the application export tree for the group with the given id.
        #[cfg(feature = "extensions-draft")]
        fn delete_application_export_tree<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }
    };
}

macro_rules! impl_storage_provider_virtual_clients_draft {
    () => {
        #[cfg(feature = "virtual-clients-draft")]
        fn vc_emulation_epoch_state<
            EpochId: traits::VcEpochId<CURRENT_VERSION>,
            VcEmulationEpochState: traits::VcEmulationEpochState<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
        ) -> Result<Option<VcEmulationEpochState>, Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn vc_emulation_bindings<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            VcEmulationBindings: traits::VcEmulationBindings<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<VcEmulationBindings>, Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn vc_operation_tree<
            EpochId: traits::VcEpochId<CURRENT_VERSION>,
            VcOperationTree: traits::VcOperationTree<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
        ) -> Result<Option<VcOperationTree>, Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn retained_key_package_material<
            KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
            RetainedKeyPackageMaterial: traits::RetainedKeyPackageMaterial<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<Option<RetainedKeyPackageMaterial>, Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn has_retained_key_package_material_for_epoch<
            EpochId: traits::VcEpochId<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
        ) -> Result<bool, Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_emulation_epoch_state<
            EpochId: traits::VcEpochId<CURRENT_VERSION>,
            VcEmulationEpochState: traits::VcEmulationEpochState<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
            vc_emulation_epoch_state: &VcEmulationEpochState,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_emulation_bindings<
            GroupId: traits::GroupId<CURRENT_VERSION>,
            VcEmulationBindings: traits::VcEmulationBindings<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            bindings: &VcEmulationBindings,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_operation_tree<
            EpochId: traits::VcEpochId<CURRENT_VERSION>,
            VcOperationTree: traits::VcOperationTree<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
            vc_operation_tree: &VcOperationTree,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_retained_key_package_material_batch<
            EpochId: traits::VcEpochId<CURRENT_VERSION>,
            VcOperationTree: traits::VcOperationTree<CURRENT_VERSION>,
            KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
            RetainedKeyPackageMaterial: traits::RetainedKeyPackageMaterial<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
            operation_tree: &VcOperationTree,
            materials: &[(KeyPackageRef, RetainedKeyPackageMaterial)],
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_vc_emulation_state_if_unreferenced<
            EpochId: traits::VcEpochId<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
        ) -> Result<bool, Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_vc_emulation_bindings<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_retained_key_package_material<
            KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<(), Self::Error> {
            unimplemented!()
        }
    };
}

use openmls_traits::storage::CURRENT_VERSION;

mod current {
    use super::{TestStorageProvider as Storage, CURRENT_VERSION as PREVIOUS_VERSION, *};
    use openmls_traits::storage::{traits, StorageProvider};

    impl StorageProvider<CURRENT_VERSION> for TestStorageProvider {
        impl_storage_provider_basic!();
        impl_storage_provider_extensions_draft!();
        impl_storage_provider_virtual_clients_draft!();
    }

    impl Storage {
        fn all_group_ids<GroupId: traits::GroupId<CURRENT_VERSION>>(
            &self,
        ) -> Result<Vec<GroupId>, postcard::Error> {
            let data = self.0.lock().unwrap();

            data.group_state
                .keys()
                .map(|key| postcard::from_bytes::<GroupId>(key))
                .collect::<Result<Vec<_>, _>>()
        }
    }

    // ANCHOR: migration_helper_impl
    impl openmls_storage_migration::StorageMigrationHelper<PREVIOUS_VERSION, CURRENT_VERSION>
        for Storage
    {
        fn group_ids<GroupId: traits::GroupId<PREVIOUS_VERSION>>(
            &self,
        ) -> Result<Vec<GroupId>, postcard::Error> {
            // return a Vec of all `GroupId`s available as keys
            // in the storage provider
            self.all_group_ids()
        }
    }
    // ANCHOR_END: migration_helper_impl
}

mod compat {
    use super::*;
    use openmls_traits_0_4_1::storage::{traits, StorageProvider};

    impl StorageProvider<CURRENT_VERSION> for TestStorageProvider {
        impl_storage_provider_basic!();
    }
}
