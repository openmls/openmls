//! This module contains the types for building commits.
//!
//! A living design doc can be found here: https://md.cryspen.com/s/TqZXcU-gA
//!
//! we might need multiple builder types to restrict the operations (methods that can be called),
//! but that's not clear yet.
//!
//!   Can also add a (const) generic param and only impl functions for some cases
//!
//!
//! What are the general phases?
//!
//!  - build all the proposals
//!    - do some of the proposals also need a builder or can we just add them?
//!    - does this already need to lock the group?
//!      - maybe; otherwise we can build two confilicting commits in parallel
//!        - we still should validate the commit when staging it, but ideally all possible issues
//!          should have been caught before
//!          - if we can make sure that all problems have been caught, the staging can just not
//!            return an error
//!  - do the signing (io!) - consume the group
//!  - stage the commit - release the group
//!
//!  - operations for step 0:
//!    - add new proposals
//!    - add select proposals by ref (that are in group's quuee)
//!    - add all proposals from the group's quuee

use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer, storage::StorageProvider as _,
};
use tls_codec::Serialize as _;

use crate::{
    ciphersuite::{hash_ref::ProposalRef, signable::Signable as _, Secret},
    group::{
        create_commit::CommitType, diff::compute_path::PathComputationResult, CreateCommitError,
        Extension, Extensions, ExternalPubExtension, ProposalQueue, ProposalQueueError,
        QueuedProposal, RatchetTreeExtension, StagedCommit,
    },
    key_packages::KeyPackage,
    messages::{
        group_info::{GroupInfo, GroupInfoTBS},
        Commit, Welcome,
    },
    prelude::{LeafNodeParameters, LibraryError},
    schedule::{
        psk::{load_psks, PskSecret},
        JoinerSecret, KeySchedule, PreSharedKeyId,
    },
    storage::{OpenMlsProvider, StorageProvider},
    versions::ProtocolVersion,
};

use super::{
    mls_auth_content::AuthenticatedContent,
    staged_commit::{MemberStagedCommitState, StagedCommitState},
    AddProposal, CreateCommitResult, MlsGroup, MlsGroupState, MlsMessageOut, PendingCommitState,
    Proposal, Sender,
};

/// This stage is about populating the builder.
pub struct Initial {
    own_proposals: Vec<Proposal>,
    force_self_update: bool,
    leaf_node_parameters: LeafNodeParameters,

    /// Whether or not to clear the proposal queue of the group when staging the commit. Needs to
    /// be done when we include the commits that have already been queued.
    consume_proposal_store: bool,
}

/// This stage is after the PSKs were loaded, ready for validation
pub struct LoadedPsks {
    own_proposals: Vec<Proposal>,
    force_self_update: bool,
    leaf_node_parameters: LeafNodeParameters,

    /// Whether or not to clear the proposal queue of the group when staging the commit. Needs to
    /// be done when we include the commits that have already been queued.
    consume_proposal_store: bool,
    psks: Vec<(PreSharedKeyId, Secret)>,
}

/// This stage is after we validated the data, ready for staging and exporting the messages
pub struct Complete {
    result: CreateCommitResult,
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
#[derive(Debug)]
pub struct CommitBuilder<'a, T> {
    /// A mutable reference to the MlsGroup. This means that we hold an exclusive lock on the group
    /// for the lifetime of this builder.
    group: &'a mut MlsGroup,

    /// The current stage
    stage: T,
}

impl<'a, T> CommitBuilder<'a, T> {
    fn replace_stage<NextStage>(self, next_stage: NextStage) -> (T, CommitBuilder<'a, NextStage>) {
        self.map_stage(|prev_stage| (prev_stage, next_stage))
    }

    fn into_stage<NextStage>(self, next_stage: NextStage) -> CommitBuilder<'a, NextStage> {
        self.replace_stage(next_stage).1
    }

    fn take_stage(self) -> (T, CommitBuilder<'a, ()>) {
        self.replace_stage(())
    }

    fn map_stage<NextStage, Aux, F: FnOnce(T) -> (Aux, NextStage)>(
        self,
        f: F,
    ) -> (Aux, CommitBuilder<'a, NextStage>) {
        let Self { group, stage } = self;

        let (aux, stage) = f(stage);

        (aux, CommitBuilder { group, stage })
    }
}

impl MlsGroup {
    /// Returns a builder for commits.
    pub fn commit_builder(&mut self) -> CommitBuilder<Initial> {
        CommitBuilder::new(self)
    }
}

impl<'a> CommitBuilder<'a, Initial> {
    /// returns a new [`CommitBuilder`] for the given [`MlsGroup`].
    pub fn new(group: &'a mut MlsGroup) -> Self {
        Self {
            group,
            stage: Initial {
                consume_proposal_store: true,
                force_self_update: false,
                leaf_node_parameters: LeafNodeParameters::default(),
                own_proposals: vec![],
            },
        }
    }

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

    /// Adds a proposal to the proposals to be committed.
    pub fn add_proposal(mut self, proposal: Proposal) -> Self {
        self.stage.own_proposals.push(proposal);
        self
    }

    /// Adds the proposals in the iterator to the proposals to be committed.
    pub fn add_proposals(mut self, proposals: impl IntoIterator<Item = Proposal>) -> Self {
        self.stage.own_proposals.extend(proposals);
        self
    }

    /// Sets the leaf node parameters for the new leaf node in a self-update. Implies that a
    /// self-update takes place.
    pub fn leaf_node_parameters(mut self, leaf_node_parameters: LeafNodeParameters) -> Self {
        self.stage.leaf_node_parameters = leaf_node_parameters;
        self
    }

    /// Adds an Add proposal to the provided [`KeyPackage`] to the list of proposals to be
    /// committed.
    pub fn propose_add(mut self, key_package: KeyPackage) -> Self {
        self.stage
            .own_proposals
            .push(Proposal::Add(AddProposal { key_package }));
        self
    }

    /// Loads the PSKs for the PskProposals marked for inclusion and moves on to the next phase.
    pub fn load_psks<Storage: StorageProvider>(
        self,
        storage: &'a Storage,
    ) -> Result<CommitBuilder<LoadedPsks>, CreateCommitError<Storage::Error>> {
        let psk_ids: Vec<_> = self
            .stage
            .own_proposals
            .iter()
            .chain(
                self.group
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
        let psks = load_psks(storage, &self.group.resumption_psk_store, &psk_ids)?
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
                    },
                )
            })
            .1)
    }
}

impl<'a> CommitBuilder<'a, LoadedPsks> {
    /// Validates the inputs and builds the commit. The last argument `f` is a function that lets
    /// the caller filter the proposals that are considered for inclusion. This provides a way for
    /// the application to enforce custom policies in the creation of commits.
    pub fn build<E, T>(
        self,
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        signer: &impl Signer,
        f: impl FnMut(&QueuedProposal) -> bool,
    ) -> Result<CommitBuilder<'a, Complete>, CreateCommitError<T>> {
        let ciphersuite = self.group.ciphersuite();
        let sender = Sender::build_member(self.group.own_leaf_index());
        let (cur_stage, builder) = self.take_stage();
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
        let group_proposal_store_queue = builder
            .group
            .pending_proposals()
            .filter(|_| cur_stage.consume_proposal_store)
            .cloned();

        // prepare the iterator for the proposal validation and seletion function. That function
        // assumes that "earlier in the list" means "older", so since our own proposals are
        // newest, we have to put them last.
        let proposal_queue = group_proposal_store_queue.chain(own_proposals).filter(f);

        let (proposal_queue, contains_own_updates) =
            ProposalQueue::filter_proposals_without_inline(
                proposal_queue,
                builder.group.own_leaf_index,
            )
            .map_err(|e| match e {
                ProposalQueueError::LibraryError(e) => e.into(),
                ProposalQueueError::ProposalNotFound => CreateCommitError::MissingProposal,
                ProposalQueueError::UpdateFromExternalSender => {
                    CreateCommitError::WrongProposalSenderType
                }
            })?;

        // Validate the proposals by doing the following checks:

        // ValSem113: All Proposals: The proposal type must be supported by all
        // members of the group
        builder
            .group
            .public_group
            .validate_proposal_type_support(&proposal_queue)?;
        // ValSem101
        // ValSem102
        // ValSem103
        // ValSem104
        builder
            .group
            .public_group
            .validate_key_uniqueness(&proposal_queue, None)?;
        // ValSem105
        builder
            .group
            .public_group
            .validate_add_proposals(&proposal_queue)?;
        // ValSem106
        // ValSem109
        builder
            .group
            .public_group
            .validate_capabilities(&proposal_queue)?;
        // ValSem107
        // ValSem108
        builder
            .group
            .public_group
            .validate_remove_proposals(&proposal_queue)?;
        builder
            .group
            .public_group
            .validate_pre_shared_key_proposals(&proposal_queue)?;
        // Validate update proposals for member commits
        // ValSem110
        // ValSem111
        // ValSem112
        builder
            .group
            .public_group
            .validate_update_proposals(&proposal_queue, builder.group.own_leaf_index())?;

        // ValSem208
        // ValSem209
        builder
            .group
            .public_group
            .validate_group_context_extensions_proposal(&proposal_queue)?;

        let ciphersuite = builder.group.ciphersuite();
        let sender = Sender::build_member(builder.group.own_leaf_index());
        let proposal_reference_list = proposal_queue.commit_list();

        // Make a copy of the public group to apply proposals safely
        let mut diff = builder.group.public_group.empty_diff();

        // Apply proposals to tree
        let apply_proposals_values =
            diff.apply_proposals(&proposal_queue, builder.group.own_leaf_index())?;
        if apply_proposals_values.self_removed {
            return Err(CreateCommitError::CannotRemoveSelf);
        }

        let path_computation_result =
            // If path is needed, compute path values
            if apply_proposals_values.path_required
                || contains_own_updates
                || cur_stage.force_self_update
                || !cur_stage.leaf_node_parameters.is_empty()
            {
                // Process the path. This includes updating the provisional
                // group context by updating the epoch and computing the new
                // tree hash.
                diff.compute_path(
                    rand,
                crypto,
                    builder.group.own_leaf_index(),
                    apply_proposals_values.exclusion_list(),
                    &CommitType::Member,
                    &cur_stage.leaf_node_parameters,
                    signer,
                    apply_proposals_values.extensions.clone()
                )?
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

        // Build AuthenticatedContent
        let mut authenticated_content = AuthenticatedContent::commit(
            builder.group.framing_parameters(),
            sender,
            commit,
            builder.group.public_group.group_context(),
            signer,
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
            builder.group.group_epoch_secrets().init_secret(),
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
            .welcome(crypto, builder.group.ciphersuite())
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        key_schedule
            .add_context(crypto, &serialized_provisional_group_context)
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;
        let provisional_epoch_secrets = key_schedule
            .epoch_secrets(crypto, builder.group.ciphersuite())
            .map_err(|_| LibraryError::custom("Using the key schedule in the wrong state"))?;

        // Calculate the confirmation tag
        let confirmation_tag = provisional_epoch_secrets
            .confirmation_key()
            .tag(
                crypto,
                builder.group.ciphersuite(),
                diff.group_context().confirmed_transcript_hash(),
            )
            .map_err(LibraryError::unexpected_crypto_error)?;

        // Set the confirmation tag
        authenticated_content.set_confirmation_tag(confirmation_tag.clone());

        diff.update_interim_transcript_hash(ciphersuite, crypto, confirmation_tag.clone())?;

        // only computes the group info if necessary
        let group_info = if !apply_proposals_values.invitation_list.is_empty()
            || builder.group.configuration().use_ratchet_tree_extension
        {
            // Create the ratchet tree extension if necessary
            let external_pub = provisional_epoch_secrets
                .external_secret()
                .derive_external_keypair(crypto, ciphersuite)
                .map_err(LibraryError::unexpected_crypto_error)?
                .public;
            let external_pub_extension =
                Extension::ExternalPub(ExternalPubExtension::new(external_pub.into()));
            let other_extensions: Extensions =
                if builder.group.configuration().use_ratchet_tree_extension {
                    Extensions::from_vec(vec![
                        Extension::RatchetTree(RatchetTreeExtension::new(
                            diff.export_ratchet_tree(),
                        )),
                        external_pub_extension,
                    ])?
                } else {
                    Extensions::single(external_pub_extension)
                };

            // Create to-be-signed group info.
            let group_info_tbs = {
                GroupInfoTBS::new(
                    diff.group_context().clone(),
                    other_extensions,
                    confirmation_tag,
                    builder.group.own_leaf_index(),
                )
            };
            // Sign to-be-signed group info.
            Some(group_info_tbs.sign(signer)?)
        } else {
            None
        };

        // Check if new members were added and, if so, create welcome messages
        let welcome_option = if !apply_proposals_values.invitation_list.is_empty() {
            // Encrypt GroupInfo object
            let (welcome_key, welcome_nonce) = welcome_secret
                .derive_welcome_key_nonce(crypto, builder.group.ciphersuite())
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
                builder.group.own_leaf_index(),
            )?;

            // Create welcome message
            let welcome = Welcome::new(ciphersuite, encrypted_secrets, encrypted_group_info);
            Some(welcome)
        } else {
            None
        };

        let (provisional_group_epoch_secrets, provisional_message_secrets) =
            provisional_epoch_secrets.split_secrets(
                serialized_provisional_group_context,
                diff.tree_size(),
                builder.group.own_leaf_index(),
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

        let use_ratchet_tree_extension = builder.group.configuration().use_ratchet_tree_extension;

        Ok(builder.into_stage(Complete {
            result: CreateCommitResult {
                commit: authenticated_content,
                welcome_option,
                staged_commit,
                group_info: group_info.filter(|_| use_ratchet_tree_extension),
            },
        }))
    }
}

impl<'a> CommitBuilder<'a, Complete> {
    pub(crate) fn commit_result(self) -> CreateCommitResult {
        self.stage.result
    }

    /// Stages the commit and returns the protocol messages.
    pub fn stage_commit<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
    ) -> Result<CommitMessageBundle, CreateCommitError<Provider::StorageError>> {
        let Self {
            group,
            stage: Complete {
                result: create_commit_result,
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
            .map_err(CreateCommitError::KeyStoreError)?;

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

    /// Gets a the GroupInfo message. Onlt [`Some`] if... when? TODO: finish writing this comment
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

    /// Gets a the GroupInfo messsage. Only [`Some`] if TODO: when???.
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
