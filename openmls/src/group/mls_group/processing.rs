//! Processing functions of an [`MlsGroup`] for incoming messages.

use std::mem;

#[cfg(feature = "extensions-draft")]
use errors::ResolveAppDataCommitError;
use errors::{CommitToPendingProposalsError, MergePendingCommitError};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, storage::StorageProvider as _};

use crate::{
    framing::mls_content::FramedContentBody,
    group::{errors::MergeCommitError, StageCommitError, ValidationError},
    messages::group_info::GroupInfo,
    storage::OpenMlsProvider,
    tree::sender_ratchet::SenderRatchetConfiguration,
};

// `virtual-clients-draft` implies `extensions-draft`, so this gate covers
// both the sibling-commit detection and the AppDataUpdate handling below.
#[cfg(feature = "extensions-draft")]
use crate::messages::Commit;

#[cfg(feature = "extensions-draft")]
use crate::{
    component::{ComponentData, ComponentId},
    extensions::AppDataDictionary,
    messages::proposals::AppDataUpdateProposal,
};

#[cfg(feature = "extensions-draft")]
use std::collections::BTreeMap;

use super::{errors::ProcessMessageError, *};

/// Result of unprotecting an inbound message.
pub(crate) enum UnprotectedMessage {
    /// A message from another sender that has been unprotected and is ready
    /// for signature verification and content parsing.
    Unverified(Box<UnverifiedMessage>),
    /// A PrivateMessage whose sender data claims this client's own leaf. The
    /// content cannot be decrypted; callers should surface
    /// [`ProcessedMessageContent::OwnPrivateMessage`] and skip further
    /// processing.
    OwnPrivateMessage {
        epoch: GroupEpoch,
        authenticated_data: Vec<u8>,
    },
}

#[cfg(feature = "extensions-draft")]
/// Keeps the old dictionary as well as the values that are being overwritten
pub struct AppDataDictionaryUpdater<'a> {
    old_dict: Option<&'a AppDataDictionary>,
    new_entries: Option<AppDataUpdates>,
}

/// A diff of update values that can be provided to [`MlsGroup::stage_app_data_commit`] or [`CommitBuilder::with_app_data_dictionary_updates`]
///
/// [`CommitBuilder::with_app_data_dictionary_updates`]: crate::group::CommitBuilder::with_app_data_dictionary_updates
#[cfg(feature = "extensions-draft")]
#[derive(Default, Debug)]
pub struct AppDataUpdates(BTreeMap<ComponentId, Option<Vec<u8>>>);

#[cfg(feature = "extensions-draft")]
impl IntoIterator for AppDataUpdates {
    type Item = (ComponentId, Option<Vec<u8>>);

    type IntoIter = <BTreeMap<ComponentId, Option<Vec<u8>>> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(feature = "extensions-draft")]
impl AppDataUpdates {
    /// Returns the number of changes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether there are changes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(feature = "extensions-draft")]
impl<'a> AppDataDictionaryUpdater<'a> {
    /// Creates a new [`AppDataDictionaryUpdater`].
    pub fn new(old_dict: Option<&'a AppDataDictionary>) -> Self {
        Self {
            old_dict,
            new_entries: None,
        }
    }

    /// Looks up the old value for a component.
    pub fn old_value(&self, component_id: ComponentId) -> Option<&[u8]> {
        self.old_dict?.get(&component_id)
    }

    /// Helper method that returns a mutable reference to the
    /// [`AppDataUpdates`], creating the struct if it does not exist.
    fn new_entries_mut(&mut self) -> &mut AppDataUpdates {
        self.new_entries
            .get_or_insert_with(|| AppDataUpdates(BTreeMap::new()))
    }

    /// Sets a value in the new_entries. if we already have data for that component id, overwrite
    /// it. Else add it in the right position.
    pub fn set(&mut self, component_data: ComponentData) {
        let (id, data) = component_data.into_parts();

        self.new_entries_mut().0.insert(id, Some(data.into()));
    }

    /// Flags an entry in the dictionary for removal
    pub fn remove(&mut self, id: &ComponentId) {
        self.new_entries_mut().0.insert(*id, None);
    }

    /// Consumes the updater and returns just the changes, so we can pass them into
    /// [`MlsGroup::stage_app_data_commit`] or
    /// [`CommitBuilder::with_app_data_dictionary_updates`].
    /// Only returns Some if we actually called set.
    ///
    /// [`CommitBuilder::with_app_data_dictionary_updates`]: crate::group::CommitBuilder::with_app_data_dictionary_updates
    pub fn changes(self) -> Option<AppDataUpdates> {
        self.new_entries
    }
}

/// A verified Commit covering AppDataUpdate proposals that cannot be staged
/// yet.
///
/// The AppDataUpdate proposals carry diffs in an application-defined format,
/// so the application has to interpret them and compute the resulting
/// [`AppDataUpdates`] before the commit can be staged: the updated
/// [`AppDataDictionary`] becomes part of the new epoch's GroupContext and
/// feeds into the key schedule.
///
/// Returned by [`MlsGroup::process_message()`] and
/// [`PublicGroup::process_message()`] as
/// [`ProcessedMessageContent::UnresolvedAppDataCommit`]. Inspect the proposals
/// via [`Self::app_data_update_proposals()`], compute the updates with the
/// help of [`MlsGroup::app_data_dictionary_updater()`] (or
/// [`PublicGroup::app_data_dictionary_updater()`]) and resume staging via
/// [`MlsGroup::stage_app_data_commit()`] (or
/// [`PublicGroup::stage_app_data_commit()`]).
///
/// The message signature has already been verified at this point. Dropping
/// this value discards the commit.
///
/// [`PublicGroup::process_message()`]: crate::group::public_group::PublicGroup::process_message
/// [`PublicGroup::app_data_dictionary_updater()`]: crate::group::public_group::PublicGroup::app_data_dictionary_updater
/// [`PublicGroup::stage_app_data_commit()`]: crate::group::public_group::PublicGroup::stage_app_data_commit
#[cfg(feature = "extensions-draft")]
pub struct UnresolvedAppDataCommit {
    content: AuthenticatedContent,
    /// The AppDataUpdate proposals covered by the commit, with proposals sent
    /// by reference already resolved from the proposal store, sorted by
    /// component id.
    proposals: Vec<AppDataUpdateProposal>,
    #[cfg(feature = "virtual-clients-draft")]
    vc_commit_material: Option<crate::components::vc_derivation_info::VcCommitMaterial>,
}

#[cfg(feature = "extensions-draft")]
impl UnresolvedAppDataCommit {
    /// Constructs an [`UnresolvedAppDataCommit`] from verified content and the
    /// covered AppDataUpdate proposals. Used by public-group processing, which
    /// carries no virtual-clients material.
    pub(crate) fn new(
        content: AuthenticatedContent,
        proposals: Vec<AppDataUpdateProposal>,
    ) -> Self {
        Self {
            content,
            proposals,
            #[cfg(feature = "virtual-clients-draft")]
            vc_commit_material: None,
        }
    }

    /// Consumes the commit and returns the verified [`AuthenticatedContent`],
    /// so that [`PublicGroup::stage_app_data_commit`] can resume staging.
    ///
    /// [`PublicGroup::stage_app_data_commit`]: crate::group::public_group::PublicGroup::stage_app_data_commit
    pub(crate) fn into_content(self) -> AuthenticatedContent {
        self.content
    }

    /// Returns the AppDataUpdate proposals covered by the commit, sorted by
    /// component id. Proposals that were committed by reference have already
    /// been resolved from the proposal store.
    pub fn app_data_update_proposals(&self) -> impl Iterator<Item = &AppDataUpdateProposal> {
        self.proposals.iter()
    }
}

#[cfg(feature = "extensions-draft")]
impl core::fmt::Debug for UnresolvedAppDataCommit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("UnresolvedAppDataCommit");
        debug_struct
            .field("content", &self.content)
            .field("proposals", &self.proposals);
        // vc_commit_material holds secret key material, so only the epoch id
        // is printed.
        #[cfg(feature = "virtual-clients-draft")]
        debug_struct.field(
            "vc_emulation_epoch_id",
            &self
                .vc_commit_material
                .as_ref()
                .map(|material| &material.epoch_id),
        );
        debug_struct.finish_non_exhaustive()
    }
}

impl MlsGroup {
    /// Parses incoming messages from the DS. Checks for syntactic errors and
    /// makes some semantic checks as well. If the input is an encrypted
    /// message, it will be decrypted. This processing function does syntactic
    /// and semantic validation of the message. It returns a [ProcessedMessage]
    /// enum.
    ///
    #[cfg_attr(
        feature = "extensions-draft",
        doc = "A commit covering AppDataUpdate proposals is returned as\n\
        [`ProcessedMessageContent::UnresolvedAppDataCommit`], since the\n\
        application has to interpret the proposals before the commit can be\n\
        staged via [`MlsGroup::stage_app_data_commit()`].\n"
    )]
    /// # Errors:
    /// Returns an [`ProcessMessageError`] when the validation checks fail
    /// with the exact reason of the failure.
    pub fn process_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        match self.unprotect_message(provider, message)? {
            UnprotectedMessage::Unverified(m) => self.process_unverified_message(provider, *m),
            // The content cannot be decrypted and the sender claim is unauthenticated,
            // so we surface OwnPrivateMessage and skip all further processing.
            UnprotectedMessage::OwnPrivateMessage {
                epoch,
                authenticated_data,
            } => {
                let credential = self.credential()?.clone();
                #[cfg_attr(not(feature = "extensions-draft"), allow(unused_mut))]
                let mut processed = ProcessedMessage::new(
                    self.group_id().clone(),
                    epoch,
                    Sender::Member(self.own_leaf_index()),
                    authenticated_data,
                    ProcessedMessageContent::OwnPrivateMessage,
                    credential,
                    #[cfg(feature = "virtual-clients-draft")]
                    None,
                );
                #[cfg(feature = "extensions-draft")]
                if self.context().safe_aad_required() {
                    processed
                        .try_attach_safe_aad()
                        .map_err(|_| ProcessMessageError::MalformedSafeAad)?;
                }
                Ok(processed)
            }
        }
    }

    #[cfg(feature = "extensions-draft")]
    /// Returns a new helper struct for updating the app data
    pub fn app_data_dictionary_updater<'a>(&'a self) -> AppDataDictionaryUpdater<'a> {
        AppDataDictionaryUpdater::new(self.context().app_data_dict())
    }

    /// Parses and deprotects incoming messages from the DS. Checks for syntactic errors, but only
    /// performs limited semantic checks.
    pub(crate) fn unprotect_message<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        message: impl Into<ProtocolMessage>,
    ) -> Result<UnprotectedMessage, ProcessMessageError<Provider::StorageError>> {
        // Make sure we are still a member of the group
        if !self.is_active() {
            return Err(ProcessMessageError::GroupStateError(
                MlsGroupStateError::UseAfterEviction,
            ));
        }
        let message = message.into();

        // Check that handshake messages are compatible with the incoming wire format policy
        if !message.is_external()
            && message.is_handshake_message()
            && !self
                .configuration()
                .wire_format_policy()
                .incoming()
                .is_compatible_with(message.wire_format())
        {
            return Err(ProcessMessageError::IncompatibleWireFormat);
        }

        // Parse the message
        let sender_ratchet_configuration = *self.configuration().sender_ratchet_configuration();

        // Check if this message will modify the secret tree when decrypting a
        // private message
        let will_modify_secret_tree = matches!(message, ProtocolMessage::PrivateMessage(_));

        // Resolve the emulator reuse-guard context for `PrivateMessage`
        // before calling `decrypt_message` so storage errors surface as
        // `ProcessMessageError::StorageError`. `PublicMessage` carries no
        // `reuse_guard`, so the lookup is skipped for it. The binding is
        // looked up at the epoch the message was sent in: a delayed message
        // from a past epoch must be deprotected with the emulation state
        // that was bound then, not the latest one.
        #[cfg(feature = "virtual-clients-draft")]
        let emulation_state = if let ProtocolMessage::PrivateMessage(private_message) = &message {
            self.vc_emulation_state_at_epoch(provider.storage(), private_message.epoch())
                .map_err(|e| match e {
                    super::VcEmulationStateError::Storage(e) => {
                        ProcessMessageError::StorageError(e)
                    }
                    super::VcEmulationStateError::MissingEmulationEpochState => {
                        ProcessMessageError::ValidationError(
                            crate::group::ValidationError::UnableToDecrypt(
                                crate::framing::errors::MessageDecryptionError::VirtualClientsError(
                                    crate::components::vc_derivation_info::VirtualClientsError::MissingEmulationEpochState,
                                ),
                            ),
                        )
                    }
                })?
        } else {
            None
        };
        #[cfg(feature = "virtual-clients-draft")]
        let emulator_ctx: Option<crate::framing::EmulatorReuseGuardCtx<'_>> = emulation_state
            .as_ref()
            .map(|state| state.reuse_guard_inputs());

        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        //  - ValSem006
        //  - ValSem007 MembershipTag presence
        let decrypt_result = self.decrypt_message(
            provider.crypto(),
            message,
            &sender_ratchet_configuration,
            #[cfg(feature = "virtual-clients-draft")]
            emulator_ctx.as_ref(),
        )?;

        // Persist the secret tree if it was modified to ensure forward secrecy
        if will_modify_secret_tree {
            provider
                .storage()
                .write_message_secrets(self.group_id(), &self.message_secrets_store)
                .map_err(ProcessMessageError::StorageError)?;
        }

        let decrypted_message = match decrypt_result {
            InboundDecryptionResult::Decrypted(decrypted_message) => decrypted_message,
            // Own private messages short-circuit here: there is no content
            // to parse or verify.
            InboundDecryptionResult::OwnPrivateMessage {
                epoch,
                authenticated_data,
            } => {
                return Ok(UnprotectedMessage::OwnPrivateMessage {
                    epoch,
                    authenticated_data,
                });
            }
        };

        let unverified_message = self
            .public_group
            .parse_message(decrypted_message, &self.message_secrets_store)
            .map_err(ProcessMessageError::from)?;

        Ok(UnprotectedMessage::Unverified(Box::new(unverified_message)))
    }

    /// Stores a standalone proposal in the internal [ProposalStore]
    pub fn store_pending_proposal<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        proposal: QueuedProposal,
    ) -> Result<(), Storage::Error> {
        storage.queue_proposal(self.group_id(), &proposal.proposal_reference(), &proposal)?;
        // Store the proposal in in the internal ProposalStore
        self.proposal_store_mut().add(proposal);

        Ok(())
    }

    /// Returns true if there are pending proposals queued in the proposal store.
    pub fn has_pending_proposals(&self) -> bool {
        !self.proposal_store().is_empty()
    }

    /// Creates a Commit message that covers the pending proposals that are
    /// currently stored in the group's [ProposalStore]. The Commit message is
    /// created even if there are no valid pending proposals.
    ///
    /// Returns an error if there is a pending commit. Otherwise it returns a
    /// tuple of `Commit, Option<Welcome>, Option<GroupInfo>`, where `Commit`
    /// and [`Welcome`] are MlsMessages of the type [`MlsMessageOut`].
    ///
    /// [`Welcome`]: crate::messages::Welcome
    // FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn commit_to_pending_proposals<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        CommitToPendingProposalsError<Provider::StorageError>,
    > {
        self.is_operational()?;

        // Build and stage the commit using the commit builder
        // TODO #751
        let (commit, welcome, group_info) = self
            .commit_builder()
            // This forces committing to the proposals in the proposal store:
            .consume_proposal_store(true)
            .load_psks(provider.storage())?
            .build(provider.rand(), provider.crypto(), signer, |_| true)?
            .stage_commit(provider)?
            .into_contents();

        Ok((
            commit,
            // Turn the [`Welcome`] to an [`MlsMessageOut`], if there is one
            welcome.map(|welcome| MlsMessageOut::from_welcome(welcome, self.version())),
            group_info,
        ))
    }

    /// Merge a [StagedCommit] into the group after inspection. As this advances
    /// the epoch of the group, it also clears any pending commits.
    pub fn merge_staged_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        staged_commit: StagedCommit,
    ) -> Result<(), MergeCommitError<Provider::StorageError>> {
        // Check if we were removed from the group
        if staged_commit.self_removed() {
            self.group_state = MlsGroupState::Inactive;
        }
        provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(MergeCommitError::StorageError)?;

        // Update the per-epoch emulation bindings. Self-removal drops them.
        // Otherwise the epoch the commit moves the group into is bound to
        // the emulation epoch of the commit's VC leaf, or, if the commit
        // does not install a new VC leaf, to the binding of the current
        // epoch, since the VC leaf stays active across commits by other
        // members.
        #[cfg(feature = "virtual-clients-draft")]
        if staged_commit.self_removed() {
            provider
                .storage()
                .delete_vc_emulation_bindings(self.group_id())
                .map_err(|e| {
                    log::error!("vc: drop emulation bindings on self-removal failed: {e:?}");
                    MergeCommitError::StorageError(e)
                })?;
        } else {
            let mut bindings: crate::components::vc_derivation_info::VcEmulationBindings = provider
                .storage()
                .vc_emulation_bindings(self.group_id())
                .map_err(MergeCommitError::StorageError)?
                .unwrap_or_default();
            let epoch_id = staged_commit
                .vc_emulation_epoch_id
                .clone()
                .or_else(|| bindings.get(self.epoch()).cloned());
            if let Some(epoch_id) = epoch_id {
                // Keep one entry per retained message-secrets epoch plus
                // the new current one, so bindings age out in lockstep
                // with the message secrets they are needed for.
                let max_entries = self.message_secrets_store.max_epochs.saturating_add(1);
                bindings.insert(staged_commit.epoch(), epoch_id, max_entries);
                provider
                    .storage()
                    .write_vc_emulation_bindings(self.group_id(), &bindings)
                    .map_err(|e| {
                        log::error!("vc: persist emulation bindings at merge failed: {e:?}");
                        MergeCommitError::StorageError(e)
                    })?;
            }
        }

        // Merge staged commit
        self.merge_commit(provider, staged_commit)?;

        // Extract and store the resumption psk for the current epoch
        let resumption_psk = self.group_epoch_secrets().resumption_psk();
        self.resumption_psk_store
            .add(self.context().epoch(), resumption_psk.clone());
        provider
            .storage()
            .write_resumption_psk_store(self.group_id(), &self.resumption_psk_store)
            .map_err(MergeCommitError::StorageError)?;

        // Delete own KeyPackageBundles
        self.own_leaf_nodes.clear();
        provider
            .storage()
            .delete_own_leaf_nodes(self.group_id())
            .map_err(MergeCommitError::StorageError)?;

        // Delete a potential pending commit
        self.clear_pending_commit(provider.storage())
            .map_err(MergeCommitError::StorageError)?;

        Ok(())
    }

    /// Merges the pending [`StagedCommit`] if there is one, and
    /// clears the field by setting it to `None`.
    pub fn merge_pending_commit<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
    ) -> Result<(), MergePendingCommitError<Provider::StorageError>> {
        match &self.group_state {
            MlsGroupState::PendingCommit(_) => {
                let old_state = mem::replace(&mut self.group_state, MlsGroupState::Operational);
                if let MlsGroupState::PendingCommit(pending_commit_state) = old_state {
                    self.merge_staged_commit(provider, (*pending_commit_state).into())?;
                }
                Ok(())
            }
            MlsGroupState::Inactive => Err(MlsGroupStateError::UseAfterEviction)?,
            MlsGroupState::Operational => Ok(()),
        }
    }

    /// Resolve a commit's virtual-clients derivation info to the per-commit
    /// `OperationSecret` the receiver needs in order to recreate the path of a
    /// commit sent by a sibling emulator client, plus the `EpochId` the
    /// commit binds the group to on merge.
    ///
    /// See [`is_sibling_vc_commit`] for the precondition the caller must
    /// check before invoking this helper. Sibling commits come in two
    /// shapes:
    ///
    ///   * own-leaf VC commits, where a sibling emulator committed through our
    ///     shared higher-level leaf
    ///   * sibling-resync external commits, where a sibling emulator joined this
    ///     higher-level group externally onto a leaf of their own,
    ///     inline-removing our previous leaf.
    ///
    /// Returns `Ok(None)` when the commit carries no virtual-clients
    /// derivation-info entry on its update-path leaf (path-less commits, or
    /// commits without an `app_data_dictionary`). Otherwise:
    ///   - looks up the per-epoch `EmulationEpochState` and operation secret
    ///     tree the application registered via `register_vc_emulation_epoch`,
    ///   - decrypts the wrapped `DerivationInfoTbe` with the AEAD key/nonce
    ///     derived from the epoch encryption key and the path leaf's
    ///     serialized encryption key,
    ///   - derives the operation secret positionally from the tree at the
    ///     sender's emulation-leaf coordinates and persists the advanced
    ///     tree,
    ///   - returns the resulting `OperationSecret` and `EpochId`.
    ///
    /// A generation the tree reports as already consumed fails with
    /// `OperationGenerationConsumed`. Operation secrets are consume-once,
    /// matching the semantics of regular PrivateMessage decryption.
    #[cfg(feature = "virtual-clients-draft")]
    pub(super) fn load_vc_commit_material<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        commit: &Commit,
    ) -> Result<Option<crate::components::vc_derivation_info::VcCommitMaterial>, StageCommitError>
    {
        use tls_codec::{DeserializeBytes, Serialize as _};

        use crate::{
            components::vc_derivation_info::{
                DerivationInfo, EmulationEpochState, VirtualClientOperationType,
                VirtualClientsError, VC_COMPONENT_ID,
            },
            components::vc_operation_tree::OperationSecretTree,
            treesync::node::leaf_node::LeafNodeSource,
        };

        let Some(path) = commit.path.as_ref() else {
            return Ok(None);
        };
        let Some(app_data_dict) = path.leaf_node().extensions().app_data_dictionary() else {
            return Ok(None);
        };
        let Some(derivation_info_bytes) = app_data_dict.dictionary().get(&VC_COMPONENT_ID) else {
            return Ok(None);
        };
        let derivation_info = DerivationInfo::tls_deserialize_exact_bytes(derivation_info_bytes)
            .map_err(|e| {
                log::error!("vc: derivation info deserialize failed: {e:?}");
                VirtualClientsError::DerivationInfoMalformed
            })?;

        let epoch_id = derivation_info.epoch_id();
        let storage = provider.storage();
        let state: EmulationEpochState = storage
            .vc_emulation_epoch_state(epoch_id)
            .map_err(|e| {
                log::error!("vc: load emulation epoch state failed: {e:?}");
                VirtualClientsError::StorageError
            })?
            .ok_or(VirtualClientsError::MissingEmulationEpochState)?;
        let mut operation_tree: OperationSecretTree = storage
            .vc_operation_tree(epoch_id)
            .map_err(|e| {
                log::error!("vc: load operation tree failed: {e:?}");
                VirtualClientsError::StorageError
            })?
            .ok_or(VirtualClientsError::MissingOperationTree)?;
        // The receiver uses the emulation epoch's AEAD key and ciphersuite
        // for `DerivationInfoTbe`. The sender's emulation leaf index travels
        // on the wire, so it doesn't have to come from storage on this side.
        let (_state_leaf_index, epoch_encryption_key, emulation_ciphersuite) = state.into_parts();

        let crypto = provider.crypto();
        let leaf_encryption_key = path
            .leaf_node()
            .encryption_key()
            .tls_serialize_detached()
            .map_err(VirtualClientsError::from)?;
        // The operation type is not on the wire. It is inferred from the
        // carrying leaf's source: key-package leaves map to `KeyPackage`,
        // update and commit leaves map to `LeafNode`. Only `LeafNode` is
        // wired up today, and an update-path leaf always has a commit
        // source. It selects the tagless `DerivationInfoTbe` variant the
        // plaintext decodes into.
        let operation_type = match path.leaf_node().leaf_node_source() {
            LeafNodeSource::KeyPackage(_) => {
                log::error!("vc: key-package leaf on an update path");
                return Err(VirtualClientsError::DerivationInfoMalformed.into());
            }
            LeafNodeSource::Update | LeafNodeSource::Commit(_) => {
                VirtualClientOperationType::LeafNode
            }
        };
        let tbe = derivation_info.decrypt(
            crypto,
            emulation_ciphersuite,
            &epoch_encryption_key,
            &leaf_encryption_key,
            operation_type,
        )?;
        // Carried by an external commit's leaf only; `None` for own-leaf
        // (regular) VC commits. A sibling uses it as the new epoch's external
        // init secret instead of decapsulating from the previous epoch's
        // `external_secret`.
        let external_init_secret = tbe.external_init_secret().cloned();
        // The operation context for `LeafNode` operations is the
        // higher-level group's id.
        let operation_context = self.group_id().as_slice().to_vec();

        // An already-consumed generation propagates as a hard error here:
        // operation secrets are consume-once, like the per-generation keys
        // of regular PrivateMessage decryption.
        let operation_secret = operation_tree.derive_operation_secret(
            crypto,
            emulation_ciphersuite,
            epoch_id,
            tbe.leaf_index(),
            operation_type,
            tbe.generation(),
            &operation_context,
        )?;
        // Persist the advanced tree immediately, before any key material is
        // derived from the secret.
        storage
            .write_vc_operation_tree(epoch_id, &operation_tree)
            .map_err(|e| {
                log::error!("vc: persist advanced operation tree failed: {e:?}");
                VirtualClientsError::StorageError
            })?;

        Ok(Some(
            crate::components::vc_derivation_info::VcCommitMaterial {
                epoch_id: epoch_id.clone(),
                operation_secret,
                external_init_secret,
            },
        ))
    }

    /// Helper function to read decryption keypairs.
    pub(super) fn read_decryption_keypairs(
        &self,
        provider: &impl OpenMlsProvider,
        own_leaf_nodes: &[LeafNode],
    ) -> Result<(Vec<EncryptionKeyPair>, Vec<EncryptionKeyPair>), StageCommitError> {
        // All keys from the previous epoch are potential decryption keypairs.
        let old_epoch_keypairs = self.read_epoch_keypairs(provider.storage()).map_err(|e| {
            log::error!("Error reading epoch keypairs: {e:?}");
            StageCommitError::MissingDecryptionKey
        })?;

        // If we are processing an update proposal that originally came from
        // us, the keypair corresponding to the leaf in the update is also a
        // potential decryption keypair.
        let leaf_node_keypairs = own_leaf_nodes
            .iter()
            .map(|leaf_node| {
                EncryptionKeyPair::read(provider, leaf_node.encryption_key())
                    .ok_or(StageCommitError::MissingDecryptionKey)
            })
            .collect::<Result<Vec<EncryptionKeyPair>, StageCommitError>>()?;

        Ok((old_epoch_keypairs, leaf_node_keypairs))
    }

    /// Stages a Commit covering AppDataUpdate proposals, after the application
    /// has interpreted the proposals and computed the resulting
    /// [`AppDataUpdates`].
    ///
    /// The returned [`StagedCommit`] can be inspected and merged into the
    /// group's state using [`MlsGroup::merge_staged_commit()`].
    #[cfg(feature = "extensions-draft")]
    pub fn stage_app_data_commit<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        unresolved_commit: UnresolvedAppDataCommit,
        app_data_dict_updates: Option<AppDataUpdates>,
    ) -> Result<StagedCommit, StageCommitError> {
        let content = unresolved_commit.content;
        #[cfg(feature = "virtual-clients-draft")]
        let vc_commit_material = unresolved_commit.vc_commit_material;

        let (old_epoch_keypairs, leaf_node_keypairs) =
            self.read_decryption_keypairs(provider, &self.own_leaf_nodes)?;

        self.stage_commit_with_app_data_updates(
            &content,
            old_epoch_keypairs,
            leaf_node_keypairs,
            app_data_dict_updates,
            provider,
            #[cfg(feature = "virtual-clients-draft")]
            vc_commit_material,
        )
    }

    /// Resolves a [`ProcessedMessage`] carrying an
    /// [`ProcessedMessageContent::UnresolvedAppDataCommit`]: stages the commit
    /// with the application-computed [`AppDataUpdates`] and returns the same
    /// message with the resulting [`StagedCommit`] as regular
    /// [`ProcessedMessageContent::StagedCommitMessage`] content. All other
    /// message fields (sender, credential, authenticated data) are preserved.
    ///
    /// Use this instead of [`MlsGroup::stage_app_data_commit()`] when the
    /// caller needs the resolved commit in [`ProcessedMessage`] form, e.g. to
    /// keep a single code path for commits with and without AppDataUpdate
    /// proposals.
    ///
    /// Returns an error if the message content is not an unresolved app data
    /// commit; the message is consumed either way.
    #[cfg(feature = "extensions-draft")]
    pub fn resolve_app_data_commit<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        processed_message: ProcessedMessage,
        app_data_dict_updates: Option<AppDataUpdates>,
    ) -> Result<ProcessedMessage, ResolveAppDataCommitError> {
        processed_message.resolve_app_data_commit(|unresolved_commit| {
            self.stage_app_data_commit(provider, unresolved_commit, app_data_dict_updates)
        })
    }

    /// This processing function does most of the semantic verifications.
    /// It returns a [ProcessedMessage] enum.
    ///
    /// Checks the following semantic validation:
    ///  - ValSem008
    ///  - ValSem010
    ///  - ValSem101
    ///  - ValSem102
    ///  - ValSem104
    ///  - ValSem106
    ///  - ValSem107
    ///  - ValSem108
    ///  - ValSem110
    ///  - ValSem111
    ///  - ValSem112
    ///  - ValSem113: All Proposals: The proposal type must be supported by all
    ///    members of the group
    ///  - ValSem200
    ///  - ValSem201
    ///  - ValSem202: Path must be the right length
    ///  - ValSem203: Path secrets must decrypt correctly
    ///  - ValSem204: Public keys from Path must be verified and match the
    ///    private keys from the direct path
    ///  - ValSem205
    pub(crate) fn process_unverified_message<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        unverified_message: UnverifiedMessage,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        // Checks the following semantic validation:
        //  - ValSem010
        //  - ValSem246 (as part of ValSem010)
        //  - https://validation.openmls.tech/#valn1302
        //  - https://validation.openmls.tech/#valn1304
        let verified =
            unverified_message.verify(self.ciphersuite(), provider.crypto(), self.version())?;

        #[cfg_attr(not(feature = "extensions-draft"), allow(unused_mut))]
        let mut processed = match verified.content.sender() {
            Sender::Member(_) | Sender::NewMemberProposal | Sender::NewMemberCommit => self
                .process_internal_authenticated_content(
                    provider,
                    verified.content,
                    verified.credential,
                    #[cfg(feature = "virtual-clients-draft")]
                    verified.emulator_sender_leaf_index,
                )?,
            Sender::External(_) => self.process_external_authenticated_content(
                provider,
                verified.content,
                verified.credential,
            )?,
        };
        #[cfg(feature = "extensions-draft")]
        if self.context().safe_aad_required() {
            processed
                .try_attach_safe_aad()
                .map_err(|_| ProcessMessageError::MalformedSafeAad)?;
        }
        Ok(processed)
    }

    fn process_internal_authenticated_content<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        content: AuthenticatedContent,
        credential: Credential,
        #[cfg(feature = "virtual-clients-draft")] emulator_sender_leaf_index: Option<LeafNodeIndex>,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        let sender = content.sender().clone();
        let authenticated_data = content.authenticated_data().to_owned();
        let epoch = content.epoch();

        let content = match content.content() {
            FramedContentBody::Application(application_message) => {
                ProcessedMessageContent::ApplicationMessage(ApplicationMessage::new(
                    application_message.as_slice().to_owned(),
                ))
            }
            FramedContentBody::Proposal(_) => {
                let proposal = Box::new(QueuedProposal::from_authenticated_content_by_ref(
                    self.ciphersuite(),
                    provider.crypto(),
                    content,
                )?);

                if matches!(sender, Sender::NewMemberProposal) {
                    ProcessedMessageContent::ExternalJoinProposalMessage(proposal)
                } else {
                    ProcessedMessageContent::ProposalMessage(proposal)
                }
            }
            FramedContentBody::Commit(commit) => {
                // Load virtual-client derivation info when this commit was
                // authored by a sibling emulator through a leaf shared with us.
                // A Commit with an UpdatePath carrying this material is staged
                // via the VC path below rather than treated as our own (see the
                // own-commit handling further down). The receiver only loads it
                // when the commit shape lets it identify itself as a sibling:
                //
                // * `Sender::Member(idx)` with `idx == own_leaf_index`: the
                //   sender committed through our shared higher-level leaf, so
                //   we are a sibling.
                // * `Sender::NewMemberCommit` with an inline `Remove(own_leaf)`:
                //   the sender is a sibling joining externally and the
                //   auto-Remove targets our previous leaf, so we are the
                //   sibling being resynced.
                #[cfg(feature = "virtual-clients-draft")]
                let vc_commit_material =
                    if is_sibling_vc_commit(commit, &sender, self.own_leaf_index()) {
                        self.load_vc_commit_material(provider, commit)?
                    } else {
                        None
                    };

                let is_own_commit =
                    matches!(&sender, Sender::Member(member) if member == &self.own_leaf_index());
                #[cfg(feature = "virtual-clients-draft")]
                let is_own_commit = is_own_commit && vc_commit_material.is_none();

                if is_own_commit {
                    let received_tag = content
                        .confirmation_tag()
                        .ok_or(StageCommitError::ConfirmationTagMissing)?;
                    if self.matches_pending_commit(received_tag) {
                        // The Commit is our pending commit this client got
                        // fanned out by the delivery service: surface
                        // `OwnPendingCommit` so the caller merges the pending
                        // commit instead of staging the fanned-out Commit.
                        return Ok(ProcessedMessage::new(
                            self.group_id().clone(),
                            epoch,
                            sender,
                            authenticated_data,
                            ProcessedMessageContent::OwnPendingCommit,
                            credential,
                            #[cfg(feature = "virtual-clients-draft")]
                            emulator_sender_leaf_index,
                        ));
                    }
                    // Not our pending commit. We cannot decrypt a path we
                    // encrypted to the other members, so a Commit with an
                    // UpdatePath is unprocessable. A Commit without an
                    // UpdatePath carries no author-private material and falls
                    // through to staging (a sibling's Commit without an
                    // UpdatePath, or our own commit replayed after the pending
                    // commit was cleared).
                    if commit.path.is_some() {
                        return Err(StageCommitError::OwnCommitMismatch.into());
                    }
                }

                // A commit covering AppDataUpdate proposals cannot be staged
                // immediately: the proposals contain diffs in an
                // application-defined format, so the application has to
                // interpret them and supply the resulting dictionary entries
                // first. The verified content is handed back to the caller,
                // who resumes staging via `MlsGroup::stage_app_data_commit`.
                #[cfg(feature = "extensions-draft")]
                {
                    let app_data_update_proposals =
                        committed_app_data_update_proposals(commit, self.proposal_store());
                    if !app_data_update_proposals.is_empty() {
                        let unresolved_commit = UnresolvedAppDataCommit {
                            content,
                            proposals: app_data_update_proposals,
                            #[cfg(feature = "virtual-clients-draft")]
                            vc_commit_material,
                        };
                        return Ok(ProcessedMessage::new(
                            self.group_id().clone(),
                            epoch,
                            sender,
                            authenticated_data,
                            ProcessedMessageContent::UnresolvedAppDataCommit(Box::new(
                                unresolved_commit,
                            )),
                            credential,
                            #[cfg(feature = "virtual-clients-draft")]
                            emulator_sender_leaf_index,
                        ));
                    }
                }

                // Since this is a commit, we need to load the private key material we need for decryption.
                let (old_epoch_keypairs, leaf_node_keypairs) =
                    self.read_decryption_keypairs(provider, &self.own_leaf_nodes)?;

                let staged_commit = self.stage_commit(
                    &content,
                    old_epoch_keypairs,
                    leaf_node_keypairs,
                    provider,
                    #[cfg(feature = "virtual-clients-draft")]
                    vc_commit_material,
                )?;

                ProcessedMessageContent::StagedCommitMessage(Box::new(staged_commit))
            }
        };

        Ok(ProcessedMessage::new(
            self.group_id().clone(),
            epoch,
            sender,
            authenticated_data,
            content,
            credential,
            #[cfg(feature = "virtual-clients-draft")]
            emulator_sender_leaf_index,
        ))
    }

    ///  - ValSem240
    ///  - ValSem241
    ///  - ValSem242
    ///  - ValSem244
    ///  - ValSem246 (as part of ValSem010)
    fn process_external_authenticated_content<Provider: OpenMlsProvider>(
        &self,
        provider: &Provider,
        content: AuthenticatedContent,
        credential: Credential,
    ) -> Result<ProcessedMessage, ProcessMessageError<Provider::StorageError>> {
        #[cfg(feature = "virtual-clients-draft")]
        let emulator_sender_leaf_index: Option<crate::binary_tree::LeafNodeIndex> = None;
        let sender = content.sender().clone();
        let data = content.authenticated_data().to_owned();

        debug_assert!(matches!(sender, Sender::External(_)));

        // https://validation.openmls.tech/#valn1501
        match content.content() {
            FramedContentBody::Application(_) => {
                Err(ProcessMessageError::UnauthorizedExternalApplicationMessage)
            }
            // TODO: https://validation.openmls.tech/#valn1502
            FramedContentBody::Proposal(Proposal::GroupContextExtensions(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        provider.crypto(),
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                    #[cfg(feature = "virtual-clients-draft")]
                    emulator_sender_leaf_index,
                ))
            }

            FramedContentBody::Proposal(Proposal::Remove(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        provider.crypto(),
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                    #[cfg(feature = "virtual-clients-draft")]
                    emulator_sender_leaf_index,
                ))
            }
            FramedContentBody::Proposal(Proposal::Add(_)) => {
                let content = ProcessedMessageContent::ProposalMessage(Box::new(
                    QueuedProposal::from_authenticated_content_by_ref(
                        self.ciphersuite(),
                        provider.crypto(),
                        content,
                    )?,
                ));
                Ok(ProcessedMessage::new(
                    self.group_id().clone(),
                    self.context().epoch(),
                    sender,
                    data,
                    content,
                    credential,
                    #[cfg(feature = "virtual-clients-draft")]
                    emulator_sender_leaf_index,
                ))
            }
            // TODO #151/#106
            FramedContentBody::Proposal(_) => Err(ProcessMessageError::UnsupportedProposalType),
            FramedContentBody::Commit(_) => {
                Err(ProcessMessageError::UnauthorizedExternalCommitMessage)
            }
        }
    }

    /// Performs framing validation and, if necessary, decrypts the given message.
    ///
    /// Returns the [`InboundDecryptionResult`] if processing is successful, or a
    /// [`ValidationError`] if it is not.
    ///
    /// Checks the following semantic validation:
    ///  - ValSem002
    ///  - ValSem003
    ///  - ValSem006
    ///  - ValSem007 MembershipTag presence
    ///  - https://validation.openmls.tech/#valn1202
    pub(crate) fn decrypt_message(
        &mut self,
        crypto: &impl OpenMlsCrypto,
        message: ProtocolMessage,
        sender_ratchet_configuration: &SenderRatchetConfiguration,
        #[cfg(feature = "virtual-clients-draft")] emulator_ctx: Option<
            &crate::framing::EmulatorReuseGuardCtx<'_>,
        >,
    ) -> Result<InboundDecryptionResult, ValidationError> {
        // Checks the following semantic validation:
        //  - ValSem002
        //  - ValSem003
        self.public_group.validate_framing(&message)?;

        let epoch = message.epoch();

        // Checks the following semantic validation:
        //  - ValSem006
        //  - ValSem007 MembershipTag presence
        match message {
            ProtocolMessage::PublicMessage(public_message) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first.
                let message_secrets =
                    self.message_secrets_for_epoch(epoch).map_err(|e| match e {
                        SecretTreeError::TooDistantInThePast => ValidationError::NoPastEpochData,
                        _ => LibraryError::custom(
                            "Unexpected error while retrieving message secrets for epoch.",
                        )
                        .into(),
                    })?;
                DecryptedMessage::from_inbound_public_message(
                    *public_message,
                    message_secrets,
                    message_secrets.serialized_context().to_vec(),
                    crypto,
                    self.ciphersuite(),
                )
                .map(InboundDecryptionResult::Decrypted)
            }
            ProtocolMessage::PrivateMessage(ciphertext) => {
                // If the message is older than the current epoch, we need to fetch the correct secret tree first
                DecryptedMessage::from_inbound_ciphertext(
                    ciphertext,
                    crypto,
                    self,
                    sender_ratchet_configuration,
                    #[cfg(feature = "virtual-clients-draft")]
                    emulator_ctx,
                )
            }
        }
    }
}

/// Collects the AppDataUpdate proposals covered by a commit, sorted by
/// component id.
///
/// Proposals sent by reference are resolved from the proposal store. A
/// reference that cannot be resolved is skipped here: staging fails on it
/// later with the regular missing-proposal error, so it does not need to be
/// surfaced at detection time.
#[cfg(feature = "extensions-draft")]
pub(crate) fn committed_app_data_update_proposals(
    commit: &Commit,
    proposal_store: &ProposalStore,
) -> Vec<AppDataUpdateProposal> {
    use crate::messages::proposals::ProposalOrRef;

    let mut proposals: Vec<AppDataUpdateProposal> = commit
        .proposals
        .iter()
        .filter_map(|proposal_or_ref| match proposal_or_ref {
            ProposalOrRef::Proposal(proposal) => match proposal.as_ref() {
                Proposal::AppDataUpdate(proposal) => Some(proposal.as_ref().clone()),
                _ => None,
            },
            ProposalOrRef::Reference(reference) => proposal_store
                .proposals()
                .find(|queued_proposal| {
                    queued_proposal.proposal_reference_ref() == reference.as_ref()
                })
                .and_then(|queued_proposal| match queued_proposal.proposal() {
                    Proposal::AppDataUpdate(proposal) => Some(proposal.as_ref().clone()),
                    _ => None,
                }),
        })
        .collect();

    proposals.sort_by_key(|proposal| proposal.component_id());
    proposals
}

/// Determines from the commit's shape whether the receiver is a sibling virtual
/// client of the sender of a virtual-clients commit.
///
/// Returns `true` for:
///   * own-leaf commits (`Sender::Member(idx)` with `idx == own_leaf_index`),
///     where receiver and sender share the higher-level leaf
///   * sibling-resync external commits (`Sender::NewMemberCommit` whose
///     proposal list inlines a `Remove` of `own_leaf_index`.
///
/// `false` for everything else.
#[cfg(feature = "virtual-clients-draft")]
fn is_sibling_vc_commit(
    commit: &Commit,
    sender: &super::Sender,
    own_leaf_index: crate::binary_tree::LeafNodeIndex,
) -> bool {
    use crate::messages::proposals::{Proposal, ProposalOrRef};

    match sender {
        super::Sender::Member(idx) => *idx == own_leaf_index,
        super::Sender::NewMemberCommit => commit.proposals.iter().any(|p| {
            matches!(
                p,
                ProposalOrRef::Proposal(boxed)
                    if matches!(boxed.as_ref(), Proposal::Remove(r) if r.removed() == own_leaf_index)
            )
        }),
        _ => false,
    }
}
