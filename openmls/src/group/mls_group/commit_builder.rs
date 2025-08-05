//! This module contains the commit builder types, which can be used to build regular (i.e.
//! non-external) commits. See the documentation of [`CommitBuilder`] for more information.

use std::{borrow::BorrowMut, marker::PhantomData};

use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer, storage::StorageProvider as _,
};
use tls_codec::Serialize as _;

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::{signable::Signable as _, Secret},
    framing::{FramingParameters, WireFormat},
    group::{
        diff::compute_path::{CommitType, PathComputationResult},
        CommitBuilderStageError, CreateCommitError, Extension, Extensions, ExternalPubExtension,
        ProposalQueue, ProposalQueueError, QueuedProposal, RatchetTreeExtension, StagedCommit,
        WireFormatPolicy,
    },
    key_packages::KeyPackage,
    messages::{
        group_info::{GroupInfo, GroupInfoTBS},
        Commit, Welcome,
    },
    prelude::{CredentialWithKey, LeafNodeParameters, LibraryError, NewSignerBundle},
    schedule::{
        psk::{load_psks, PskSecret},
        JoinerSecret, KeySchedule, PreSharedKeyId,
    },
    storage::{OpenMlsProvider, StorageProvider},
    versions::ProtocolVersion,
};

pub(crate) mod external_commits;

pub use external_commits::{ExternalCommitBuilder, ExternalCommitBuilderError};

#[cfg(doc)]
use super::MlsGroupJoinConfig;

use super::{
    mls_auth_content::AuthenticatedContent,
    staged_commit::{MemberStagedCommitState, StagedCommitState},
    AddProposal, CreateCommitResult, GroupContextExtensionProposal, MlsGroup, MlsGroupState,
    MlsMessageOut, PendingCommitState, Proposal, RemoveProposal, Sender,
};

#[derive(Debug)]
struct ExternalCommitInfo {
    aad: Vec<u8>,
    credential: CredentialWithKey,
    wire_format_policy: WireFormatPolicy,
}

/// This stage is for populating the builder.
#[derive(Debug)]
pub struct Initial {
    own_proposals: Vec<Proposal>,
    force_self_update: bool,
    leaf_node_parameters: LeafNodeParameters,
    create_group_info: bool,
    external_commit_info: Option<ExternalCommitInfo>,

    /// Whether or not to clear the proposal queue of the group when staging the commit. Needs to
    /// be done when we include the commits that have already been queued.
    consume_proposal_store: bool,
}

impl Default for Initial {
    fn default() -> Self {
        Initial {
            consume_proposal_store: true,
            force_self_update: false,
            leaf_node_parameters: LeafNodeParameters::default(),
            create_group_info: false,
            own_proposals: vec![],
            external_commit_info: None,
        }
    }
}

/// This stage is after the PSKs were loaded, ready for validation
pub struct LoadedPsks {
    own_proposals: Vec<Proposal>,
    force_self_update: bool,
    leaf_node_parameters: LeafNodeParameters,
    create_group_info: bool,
    external_commit_info: Option<ExternalCommitInfo>,

    /// Whether or not to clear the proposal queue of the group when staging the commit. Needs to
    /// be done when we include the commits that have already been queued.
    consume_proposal_store: bool,
    psks: Vec<(PreSharedKeyId, Secret)>,
}

/// This stage is after we validated the data, ready for staging and exporting the messages
pub struct Complete {
    result: CreateCommitResult,
    // Only for external commits
    original_wire_format_policy: Option<WireFormatPolicy>,
}

/// The [`CommitBuilder`] is used to easily and dynamically build commit messages.
/// It operates in a series of stages:
///
/// The [`Initial`] stage is used to populate the builder with proposals and other data using
/// method calls on the builder that let the builder stay in the same stage.
///
/// The next stage is [`LoadedPsks`], and it signifies the stage after the builder loaded the the
/// pre-shared keys for the PreSharedKey proposals in this commit.
///
/// Then comes the [`Complete`] stage, which denotes that all data has been validated. From this
/// stage, the commit can be staged in the group, and the outgoing messages returned.
///
/// For example, to create a commit to a new Add proposal with a KeyPackage `key_package_to_add`
/// that does not commit to the proposals in the proposal store, one could build the commit as
/// follows:
///
/// ```rust,ignore
/// let message_bundle: CommitMessageBundle = mls_group
///   .commit_builder()
///   .consume_proposal_store(false)
///   .add_proposal(key_package_to_add)
///   .load_psks(provider.storage())?
///   .build(provider.rand(), provider.crypto(), signer, app_policy_proposals)?
///   .stage_commit(provider)?;
///
/// let commit = message_bundle.commit();
/// let welcome = message_bundle.welcome().expect("expected a welcome since there was an add");
/// let group_info = message_bundle.welcome().expect("expected a group info since there was an add");
/// ```
///
/// In this example `signer` is a reference to a [`Signer`] and `app_policy_proposals` is the
/// application-defined policy for which proposals to accept, implemented by an
/// `FnMut(&QueuedProposal) -> bool`.
///
/// See the [book] for another example.
///
/// [book]: https://book.openmls.tech/user_manual/add_members.html
#[derive(Debug)]
pub struct CommitBuilder<'a, T, G: BorrowMut<MlsGroup> = &'a mut MlsGroup> {
    /// A mutable reference to the MlsGroup. This means that we hold an exclusive lock on the group
    /// for the lifetime of this builder.
    group: G,

    /// The current stage
    stage: T,

    pd: PhantomData<&'a ()>,
}

impl<'a, T, G: BorrowMut<MlsGroup>> CommitBuilder<'a, T, G> {
    pub(crate) fn replace_stage<NextStage>(
        self,
        next_stage: NextStage,
    ) -> (T, CommitBuilder<'a, NextStage, G>) {
        self.map_stage(|prev_stage| (prev_stage, next_stage))
    }

    pub(crate) fn into_stage<NextStage>(
        self,
        next_stage: NextStage,
    ) -> CommitBuilder<'a, NextStage, G> {
        self.replace_stage(next_stage).1
    }

    fn take_stage(self) -> (T, CommitBuilder<'a, (), G>) {
        self.replace_stage(())
    }

    fn map_stage<NextStage, Aux, F: FnOnce(T) -> (Aux, NextStage)>(
        self,
        f: F,
    ) -> (Aux, CommitBuilder<'a, NextStage, G>) {
        let Self {
            group,
            stage,
            pd: PhantomData,
        } = self;

        let (aux, stage) = f(stage);

        (
            aux,
            CommitBuilder {
                group,
                stage,
                pd: PhantomData,
            },
        )
    }

    #[cfg(feature = "fork-resolution")]
    pub(crate) fn stage(&self) -> &T {
        &self.stage
    }
}

impl MlsGroup {
    /// Returns a builder for commits.
    pub fn commit_builder(&mut self) -> CommitBuilder<Initial> {
        CommitBuilder::<'_, Initial, &mut MlsGroup>::new(self)
    }
}

// Impls that only apply to non-external commits.
impl<'a> CommitBuilder<'a, Initial, &mut MlsGroup> {
    /// Sets whether or not the proposals in the proposal store of the group should be included in
    /// the commit. Defaults to `true`.
    pub fn consume_proposal_store(mut self, consume_proposal_store: bool) -> Self {
        self.stage.consume_proposal_store = consume_proposal_store;
        self
    }

    /// Sets whether or not the commit should force a self-update. Defaults to `false`.
    pub fn force_self_update(mut self, force_self_update: bool) -> Self {
        self.stage.force_self_update = force_self_update;
        self
    }

    /// Adds an Add proposal to the provided [`KeyPackage`] to the list of proposals to be
    /// committed.
    pub fn propose_adds(mut self, key_packages: impl IntoIterator<Item = KeyPackage>) -> Self {
        self.stage.own_proposals.extend(
            key_packages
                .into_iter()
                .map(|key_package| Proposal::Add(AddProposal { key_package })),
        );
        self
    }

    /// Adds a Remove proposal for the provided [`LeafNodeIndex`]es to the list of proposals to be
    /// committed.
    pub fn propose_removals(mut self, removed: impl IntoIterator<Item = LeafNodeIndex>) -> Self {
        self.stage.own_proposals.extend(
            removed
                .into_iter()
                .map(|removed| Proposal::Remove(RemoveProposal { removed })),
        );
        self
    }

    /// Adds a GroupContextExtensions proposal for the provided [`Extensions`] to the list of
    /// proposals to be committed.
    pub fn propose_group_context_extensions(mut self, extensions: Extensions) -> Self {
        self.stage
            .own_proposals
            .push(Proposal::GroupContextExtensions(
                GroupContextExtensionProposal::new(extensions),
            ));
        self
    }

    /// Adds a proposal to the proposals to be committed. To add multiple
    /// proposals, use [`Self::add_proposals`].
    pub fn add_proposal(mut self, proposal: Proposal) -> Self {
        self.stage.own_proposals.push(proposal);
        self
    }

    /// Adds the proposals in the iterator to the proposals to be committed.
    pub fn add_proposals(mut self, proposals: impl IntoIterator<Item = Proposal>) -> Self {
        self.stage.own_proposals.extend(proposals);
        self
    }
}

// Impls that apply to regular and external commits.
impl<'a, G: BorrowMut<MlsGroup>> CommitBuilder<'a, Initial, G> {
    /// returns a new [`CommitBuilder`] for the given [`MlsGroup`].
    pub fn new(group: G) -> CommitBuilder<'a, Initial, G> {
        let stage = Initial {
            create_group_info: group.borrow().configuration().use_ratchet_tree_extension,
            ..Default::default()
        };
        CommitBuilder {
            group,
            stage,
            pd: PhantomData,
        }
    }

    /// Sets whether or not a [`GroupInfo`] should be created when the commit is staged. Defaults to
    /// the value of the [`MlsGroup`]s [`MlsGroupJoinConfig`].
    pub fn create_group_info(mut self, create_group_info: bool) -> Self {
        self.stage.create_group_info = create_group_info;
        self
    }

    /// Sets the leaf node parameters for the new leaf node in a self-update. Implies that a
    /// self-update takes place.
    pub fn leaf_node_parameters(mut self, leaf_node_parameters: LeafNodeParameters) -> Self {
        self.stage.leaf_node_parameters = leaf_node_parameters;
        self
    }

    /// Loads the PSKs for the PskProposals marked for inclusion and moves on to the next phase.
    pub fn load_psks<Storage: StorageProvider>(
        self,
        storage: &'a Storage,
    ) -> Result<CommitBuilder<'a, LoadedPsks, G>, CreateCommitError> {
        let psk_ids: Vec<_> = self
            .stage
            .own_proposals
            .iter()
            .chain(
                self.group
                    .borrow()
                    .proposal_store()
                    .proposals()
                    .map(|queued_proposal| queued_proposal.proposal()),
            )
            .filter_map(|proposal| match proposal {
                Proposal::PreSharedKey(psk_proposal) => Some(psk_proposal.clone().into_psk_id()),
                _ => None,
            })
            .collect();

        // Load the PSKs and make the PskIds owned.
        let psks = load_psks(storage, &self.group.borrow().resumption_psk_store, &psk_ids)?
            .into_iter()
            .map(|(psk_id_ref, key)| (psk_id_ref.clone(), key))
            .collect();

        Ok(self
            .map_stage(|stage| {
                (
                    (),
                    LoadedPsks {
                        own_proposals: stage.own_proposals,
                        psks,
                        force_self_update: stage.force_self_update,
                        leaf_node_parameters: stage.leaf_node_parameters,
                        consume_proposal_store: stage.consume_proposal_store,
                        create_group_info: stage.create_group_info,
                        external_commit_info: stage.external_commit_info,
                    },
                )
            })
            .1)
    }
}

impl<'a, G: BorrowMut<MlsGroup>> CommitBuilder<'a, LoadedPsks, G> {
    /// Validates the inputs and builds the commit. The last argument `f` is a function that lets
    /// the caller filter the proposals that are considered for inclusion. This provides a way for
    /// the application to enforce custom policies in the creation of commits.
    pub fn build<S: Signer>(
        self,
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        signer: &S,
        f: impl FnMut(&QueuedProposal) -> bool,
    ) -> Result<CommitBuilder<'a, Complete, G>, CreateCommitError> {
        self.build_internal(rand, crypto, signer, None::<NewSignerBundle<'_, S>>, f)
    }

    /// Just like `build`, this function validates the inputs and builds the
    /// commit. The last argument `f` is a function that lets the caller filter
    /// the proposals that are considered for inclusion. This provides a way for
    /// the application to enforce custom policies in the creation of commits.
    ///
    /// In contrast to `build`, this function can be used to create commits that
    /// rotate the own leaf node's signature key.
    pub fn build_with_new_signer<S: Signer>(
        self,
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        old_signer: &impl Signer,
        new_signer: NewSignerBundle<'_, S>,
        f: impl FnMut(&QueuedProposal) -> bool,
    ) -> Result<CommitBuilder<'a, Complete, G>, CreateCommitError> {
        self.build_internal(rand, crypto, old_signer, Some(new_signer), f)
    }

    fn build_internal<S: Signer>(
        self,
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        old_signer: &impl Signer,
        new_signer: Option<NewSignerBundle<'_, S>>,
        f: impl FnMut(&QueuedProposal) -> bool,
    ) -> Result<CommitBuilder<'a, Complete, G>, CreateCommitError> {
        let (mut cur_stage, builder) = self.take_stage();
        let group = builder.group.borrow();
        let ciphersuite = group.ciphersuite();
        let own_leaf_index = group.own_leaf_index();
        let (sender, is_external_commit) = match cur_stage.external_commit_info {
            None => (Sender::build_member(own_leaf_index), false),
            Some(_) => (Sender::NewMemberCommit, true),
        };
        let psks = cur_stage.psks;

        // put the pending and uniform proposals into a uniform shape,
        // i.e. produce queued proposals from the own proposals
        let own_proposals: Vec<_> = cur_stage
            .own_proposals
            .into_iter()
            .map(|proposal| {
                QueuedProposal::from_proposal_and_sender(ciphersuite, crypto, proposal, &sender)
            })
            .collect::<Result<_, _>>()?;

        // prepare an iterator for the proposals in the group's proposal store, but only if the
        // flag is set.
        let group_proposal_store_queue = group
            .pending_proposals()
            .filter(|_| cur_stage.consume_proposal_store)
            .cloned();

        // prepare the iterator for the proposal validation and seletion function. That function
        // assumes that "earlier in the list" means "older", so since our own proposals are
        // newest, we have to put them last.
        let proposal_queue = group_proposal_store_queue.chain(own_proposals).filter(f);

        let (proposal_queue, contains_own_updates) =
            ProposalQueue::filter_proposals(proposal_queue, group.own_leaf_index).map_err(|e| {
                match e {
                    ProposalQueueError::LibraryError(e) => e.into(),
                    ProposalQueueError::ProposalNotFound => CreateCommitError::MissingProposal,
                    ProposalQueueError::UpdateFromExternalSender
                    | ProposalQueueError::SelfRemoveFromNonMember => {
                        CreateCommitError::WrongProposalSenderType
                    }
                }
            })?;

        // Validate the proposals by doing the following checks:

        // ValSem113: All Proposals: The proposal type must be supported by all
        // members of the group
        group
            .public_group
            .validate_proposal_type_support(&proposal_queue)?;
        // ValSem101
        // ValSem102
        // ValSem103
        // ValSem104
        group
            .public_group
            .validate_key_uniqueness(&proposal_queue, None)?;
        // ValSem105
        group.public_group.validate_add_proposals(&proposal_queue)?;
        // ValSem106
        // ValSem109
        group.public_group.validate_capabilities(&proposal_queue)?;
        // ValSem107
        // ValSem108
        group
            .public_group
            .validate_remove_proposals(&proposal_queue)?;
        group
            .public_group
            .validate_pre_shared_key_proposals(&proposal_queue)?;
        // Validate update proposals for member commits
        // ValSem110
        // ValSem111
        // ValSem112
        group
            .public_group
            .validate_update_proposals(&proposal_queue, own_leaf_index)?;

        // ValSem208
        // ValSem209
        group
            .public_group
            .validate_group_context_extensions_proposal(&proposal_queue)?;

        if is_external_commit {
            group
                .public_group
                .validate_external_commit(&proposal_queue)?;
        }

        let proposal_reference_list = proposal_queue.commit_list();

        // Make a copy of the public group to apply proposals safely
        let mut diff = group.public_group.empty_diff();

        // Apply proposals to tree
        let apply_proposals_values = diff.apply_proposals(&proposal_queue, own_leaf_index)?;
        if apply_proposals_values.self_removed && !is_external_commit {
            return Err(CreateCommitError::CannotRemoveSelf);
        }

        let path_computation_result =
            // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || cur_stage.force_self_update
                || !cur_stage.leaf_node_parameters.is_empty()
            {
                let commit_type = match &cur_stage.external_commit_info {
                    Some(ExternalCommitInfo { credential , ..}) => {
                        CommitType::External(credential.clone())
                    }
                    None => CommitType::Member,
                };
                // Process the path. This includes updating the provisional
                // group context by updating the epoch and computing the new
                // tree hash.
                if let Some(new_signer) = new_signer {
                    if let Some(credential_with_key) =
                        cur_stage.leaf_node_parameters.credential_with_key()
                    {
                        if credential_with_key != &new_signer.credential_with_key {
                            return Err(CreateCommitError::InvalidLeafNodeParameters);
                        }
                    }
                    cur_stage.leaf_node_parameters.set_credential_with_key(
                        new_signer.credential_with_key,
                    );
                    diff.compute_path(
                        rand,
                        crypto,
                        own_leaf_index,
                        apply_proposals_values.exclusion_list(),
                        &commit_type,
                        &cur_stage.leaf_node_parameters,
                        new_signer.signer,
                        apply_proposals_values.extensions.clone()
                    )?
                } else {
                    diff.compute_path(
                        rand,
                        crypto,
                        own_leaf_index,
                        apply_proposals_values.exclusion_list(),
                        &commit_type,
                        &cur_stage.leaf_node_parameters,
                        old_signer,
                        apply_proposals_values.extensions.clone()
                    )?
                }
            } else {
                // If path is not needed, update the group context and return
                // empty path processing results
                diff.update_group_context(crypto, apply_proposals_values.extensions.clone())?;
                PathComputationResult::default()
            };

        let update_path_leaf_node = path_computation_result
            .encrypted_path
            .as_ref()
            .map(|path| path.leaf_node().clone());

        // Create commit message
        let commit = Commit {
            proposals: proposal_reference_list,
            path: path_computation_result.encrypted_path,
        };

        let framing_parameters =
            if let Some(ExternalCommitInfo { aad, .. }) = &cur_stage.external_commit_info {
                FramingParameters::new(aad, WireFormat::PublicMessage)
            } else {
                group.framing_parameters()
            };

        // Build AuthenticatedContent
        let mut authenticated_content = AuthenticatedContent::commit(
            framing_parameters,
            sender,
            commit,
            group.public_group.group_context(),
            old_signer,
        )?;

        // Update the confirmed transcript hash using the commit we just created.
        diff.update_confirmed_transcript_hash(crypto, &authenticated_content)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let joiner_secret = JoinerSecret::new(
            crypto,
            ciphersuite,
            path_computation_result.commit_secret,
            group.group_epoch_secrets().init_secret(),
            &serialized_provisional_group_context,
        )
        .map_err(LibraryError::unexpected_crypto_error)?;

        // Prepare the PskSecret
        let psk_secret = { PskSecret::new(crypto, ciphersuite, psks)? };

        // Create key schedule
        let mut key_schedule = KeySchedule::init(ciphersuite, crypto, &joiner_secret, psk_secret)?;

        let serialized_provisional_group_context = diff
            .group_context()
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;

        let welcome_secret = key_schedule
            .welcome(crypto, ciphersuite)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        key_schedule
            .add_context(crypto, &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(crypto, ciphersuite)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(
                crypto,
                ciphersuite,
                diff.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Set the confirmation tag
        authenticated_content.set_confirmation_tag(confirmation_tag.clone());

        diff.update_interim_transcript_hash(ciphersuite, crypto, confirmation_tag.clone())?;

        // If there are invitations, we need to build a welcome
        let needs_welcome = !apply_proposals_values.invitation_list.is_empty();

        // We need a GroupInfo if we need to build a Welcome, or if
        // `create_group_info` is set to `true`. If not overridden, `create_group_info`
        // is set to the `use_ratchet_tree` flag in the group configuration.
        let needs_group_info = needs_welcome || cur_stage.create_group_info;

        let group_info = if !needs_group_info {
            None
        } else {
            // Build ExternalPub extension
            let external_pub = provisional_epoch_secrets
                .external_secret()
                .derive_external_keypair(crypto, ciphersuite)
                .map_err(LibraryError::unexpected_crypto_error)?
                .public;
            let external_pub_extension =
                Extension::ExternalPub(ExternalPubExtension::new(external_pub.into()));

            // Create the ratchet tree extension if necessary
            let extensions: Extensions = if group.configuration().use_ratchet_tree_extension {
                Extensions::from_vec(vec![
                    Extension::RatchetTree(RatchetTreeExtension::new(diff.export_ratchet_tree())),
                    external_pub_extension,
                ])?
            } else {
                Extensions::single(external_pub_extension)
            };

            // Create to-be-signed group info.
            let group_info_tbs = {
                GroupInfoTBS::new(
                    diff.group_context().clone(),
                    extensions,
                    confirmation_tag,
                    own_leaf_index,
                )
            };
            // Sign to-be-signed group info.
            Some(group_info_tbs.sign(old_signer)?)
        };

        let welcome_option = if !needs_welcome {
            None
        } else {
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret
                .derive_welcome_key_nonce(crypto, ciphersuite)
                .map_err(LibraryError::unexpected_crypto_error)?;
            let encrypted_group_info = welcome_key
                .aead_seal(
                    crypto,
                    group_info
                        .as_ref()
                        .ok_or_else(|| LibraryError::custom("GroupInfo was not computed"))?
                        .tls_serialize_detached()
                        .map_err(LibraryError::missing_bound_check)?
                        .as_slice(),
                    &[],
                    &welcome_nonce,
                )
                .map_err(LibraryError::unexpected_crypto_error)?;

            // Create group secrets for later use, so we can afterwards consume the
            // `joiner_secret`.
            let encrypted_secrets = diff.encrypt_group_secrets(
                &joiner_secret,
                apply_proposals_values.invitation_list,
                path_computation_result.plain_path.as_deref(),
                &apply_proposals_values.presharedkeys,
                &encrypted_group_info,
                crypto,
                own_leaf_index,
            )?;

            // Create welcome message
            let welcome = Welcome::new(ciphersuite, encrypted_secrets, encrypted_group_info);
            Some(welcome)
        };

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.tree_size(),
                own_leaf_index,
            );

        let staged_commit_state = MemberStagedCommitState::new(
            provisional_group_epoch_secrets,
            provisional_message_secrets,
            diff.into_staged_diff(crypto, ciphersuite)?,
            path_computation_result.new_keypairs,
            // The committer is not allowed to include their own update
            // proposal, so there is no extra keypair to store here.
            None,
            update_path_leaf_node,
        );
        let staged_commit = StagedCommit::new(
            proposal_queue,
            StagedCommitState::GroupMember(Box::new(staged_commit_state)),
        );

        Ok(builder.into_stage(Complete {
            result: CreateCommitResult {
                commit: authenticated_content,
                welcome_option,
                staged_commit,
                group_info: group_info.filter(|_| cur_stage.create_group_info),
            },
            original_wire_format_policy: cur_stage
                .external_commit_info
                .as_ref()
                .map(|info| info.wire_format_policy),
        }))
    }
}

// Impls that apply only to regular commits.
impl CommitBuilder<'_, Complete, &mut MlsGroup> {
    #[cfg(test)]
    pub(crate) fn commit_result(self) -> CreateCommitResult {
        self.stage.result
    }

    /// Stages the commit and returns the protocol messages.
    pub fn stage_commit<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<CommitMessageBundle, CommitBuilderStageError<Provider::StorageError>> {
        let Self {
            group,
            stage:
                Complete {
                    result: create_commit_result,
                    original_wire_format_policy: _,
                },
            ..
        } = self;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        group.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        provider
            .storage()
            .write_group_state(group.group_id(), &group.group_state)
            .map_err(CommitBuilderStageError::KeyStoreError)?;

        group.reset_aad();

        // Convert PublicMessage messages to MLSMessage and encrypt them if required by the
        // configuration.
        //
        // Note that this performs writes to the storage, so we should do that here, rather than
        // when working with the result.
        let mls_message = group.content_to_mls_message(create_commit_result.commit, provider)?;

        Ok(CommitMessageBundle {
            version: group.version(),
            commit: mls_message,
            welcome: create_commit_result.welcome_option,
            group_info: create_commit_result.group_info,
        })
    }
}

/// Contains the messages that are produced by committing. The messages can be accessed individually
/// using getters or through the [`IntoIterator`] interface.
#[derive(Debug, Clone)]
pub struct CommitMessageBundle {
    version: ProtocolVersion,
    commit: MlsMessageOut,
    welcome: Option<Welcome>,
    group_info: Option<GroupInfo>,
}

#[cfg(test)]
impl CommitMessageBundle {
    pub fn new(
        version: ProtocolVersion,
        commit: MlsMessageOut,
        welcome: Option<Welcome>,
        group_info: Option<GroupInfo>,
    ) -> Self {
        Self {
            version,
            commit,
            welcome,
            group_info,
        }
    }
}

impl CommitMessageBundle {
    // borrowed getters

    /// Gets a the Commit messsage. For owned version, see [`Self::into_commit`].
    pub fn commit(&self) -> &MlsMessageOut {
        &self.commit
    }

    /// Gets a the Welcome messsage. Only [`Some`] if new clients have been added in the commit.
    /// For owned version, see [`Self::into_welcome`].
    pub fn welcome(&self) -> Option<&Welcome> {
        self.welcome.as_ref()
    }

    /// Gets a the Welcome messsage. Only [`Some`] if new clients have been added in the commit.
    /// Performs a copy of the Welcome. For owned version, see [`Self::into_welcome_msg`].
    pub fn to_welcome_msg(&self) -> Option<MlsMessageOut> {
        self.welcome
            .as_ref()
            .map(|welcome| MlsMessageOut::from_welcome(welcome.clone(), self.version))
    }

    /// Gets a the GroupInfo message. Only [`Some`] if new clients have been added or the group
    /// configuration has `use_ratchet_tree_extension` set.
    /// For owned version, see [`Self::into_group_info`].
    pub fn group_info(&self) -> Option<&GroupInfo> {
        self.group_info.as_ref()
    }

    /// Gets all three messages, some of which optional. For owned version, see
    /// [`Self::into_contents`].
    pub fn contents(&self) -> (&MlsMessageOut, Option<&Welcome>, Option<&GroupInfo>) {
        (
            &self.commit,
            self.welcome.as_ref(),
            self.group_info.as_ref(),
        )
    }

    // owned getters
    /// Gets a the Commit messsage. This method consumes the [`CommitMessageBundle`]. For a borrowed
    /// version see [`Self::commit`].
    pub fn into_commit(self) -> MlsMessageOut {
        self.commit
    }

    /// Gets a the Welcome messsage. Only [`Some`] if new clients have been added in the commit.
    /// This method consumes the [`CommitMessageBundle`]. For a borrowed version see
    /// [`Self::welcome`].
    pub fn into_welcome(self) -> Option<Welcome> {
        self.welcome
    }

    /// Gets a the Welcome messsage. Only [`Some`] if new clients have been added in the commit.
    /// For a borrowed version, see [`Self::to_welcome_msg`].
    pub fn into_welcome_msg(self) -> Option<MlsMessageOut> {
        self.welcome
            .map(|welcome| MlsMessageOut::from_welcome(welcome, self.version))
    }

    /// Gets a the GroupInfo message. Only [`Some`] if new clients have been added or the group
    /// configuration has `use_ratchet_tree_extension` set.
    /// This method consumes the [`CommitMessageBundle`]. For a borrowed version see
    /// [`Self::group_info`].
    pub fn into_group_info(self) -> Option<GroupInfo> {
        self.group_info
    }

    /// Gets a the GroupInfo messsage. Only [`Some`] if new clients have been added in the commit.
    pub fn into_group_info_msg(self) -> Option<MlsMessageOut> {
        self.group_info.map(|group_info| group_info.into())
    }

    /// Gets all three messages, some of which optional. This method consumes the
    /// [`CommitMessageBundle`]. For a borrowed version see [`Self::contents`].
    pub fn into_contents(self) -> (MlsMessageOut, Option<Welcome>, Option<GroupInfo>) {
        (self.commit, self.welcome, self.group_info)
    }

    /// Gets all three messages, some of which optional, as [`MlsMessageOut`].
    /// This method consumes the [`CommitMessageBundle`].
    pub fn into_messages(self) -> (MlsMessageOut, Option<MlsMessageOut>, Option<MlsMessageOut>) {
        (
            self.commit,
            self.welcome
                .map(|welcome| MlsMessageOut::from_welcome(welcome, self.version)),
            self.group_info.map(|group_info| group_info.into()),
        )
    }
}

impl IntoIterator for CommitMessageBundle {
    type Item = MlsMessageOut;

    type IntoIter = core::iter::Chain<
        core::iter::Chain<
            core::option::IntoIter<MlsMessageOut>,
            core::option::IntoIter<MlsMessageOut>,
        >,
        core::option::IntoIter<MlsMessageOut>,
    >;

    fn into_iter(self) -> Self::IntoIter {
        let welcome = self.to_welcome_msg();
        let group_info = self.group_info.map(|group_info| group_info.into());

        Some(self.commit)
            .into_iter()
            .chain(welcome)
            .chain(group_info)
    }
}
