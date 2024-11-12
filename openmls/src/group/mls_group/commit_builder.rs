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

use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, signatures::Signer};
use tls_codec::Serialize as _;

use crate::{
    ciphersuite::{hash_ref::ProposalRef, signable::Signable as _, Secret},
    group::{
        create_commit::CommitType, diff::compute_path::PathComputationResult, CreateCommitError,
        Extension, Extensions, ExternalPubExtension, ProposalQueue, ProposalQueueError,
        QueuedProposal, RatchetTreeExtension, StagedCommit,
    },
    key_packages::KeyPackage,
    messages::{group_info::GroupInfoTBS, Commit, Welcome},
    prelude::{LeafNodeParameters, LibraryError},
    schedule::{
        errors::PskError,
        psk::{load_psks, PskSecret},
        JoinerSecret, KeySchedule, PreSharedKeyId,
    },
    storage::StorageProvider,
};

use super::{
    mls_auth_content::AuthenticatedContent,
    staged_commit::{MemberStagedCommitState, StagedCommitState},
    AddProposal, CreateCommitResult, MlsGroup, Proposal, Sender,
};

/// This step is about populating the builder
pub struct Initial {
    own_proposals: Vec<Proposal>,
}

/// This step is after the PSKs were loaded
pub struct LoadedPsks {
    own_proposals: Vec<Proposal>,
    psks: Vec<(PreSharedKeyId, Secret)>,
}

/// This step is after we constructed and signed the proposals
pub struct ValidatedProposals {
    proposal_queue: ProposalQueue,
    contains_own_updates: bool,
    psks: Vec<(PreSharedKeyId, Secret)>,
}

/// This step is after we validated the data, but before staged it
pub struct Complete {
    result: CreateCommitResult,
}

#[derive(Debug)]
pub struct CommitBuilder<'a, T> {
    group: &'a mut MlsGroup,
    self_update_key_package: Option<KeyPackage>,
    included_proposal_refs: Vec<ProposalRef>,
    force_self_update: bool,
    leaf_node_parameters: LeafNodeParameters,

    /// Whether or not to clear the proposal queue of the group when staging the commit. Needs to
    /// be done when we include the commits that have already been queued.
    consume_proposal_store: bool,

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
        let Self {
            group,
            self_update_key_package,
            included_proposal_refs,
            force_self_update,
            leaf_node_parameters,
            consume_proposal_store,
            stage,
        } = self;

        let (aux, stage) = f(stage);

        (
            aux,
            CommitBuilder {
                group,
                self_update_key_package,
                included_proposal_refs,
                force_self_update,
                leaf_node_parameters,
                consume_proposal_store,
                stage,
            },
        )
    }
}

impl MlsGroup {
    /// Returns a builder for commits.
    pub fn commit_builder(&mut self) -> CommitBuilder<Initial> {
        CommitBuilder::new(self)
    }
}

impl<'a> CommitBuilder<'a, Initial> {
    pub fn new(group: &'a mut MlsGroup) -> Self {
        Self {
            group,
            self_update_key_package: None,
            consume_proposal_store: false,
            included_proposal_refs: vec![],
            force_self_update: false,
            leaf_node_parameters: LeafNodeParameters::default(),
            stage: Initial {
                own_proposals: vec![],
            },
        }
    }

    pub fn consume_proposal_store(self, consume_proposal_store: bool) -> Self {
        Self {
            consume_proposal_store,
            ..self
        }
    }

    pub fn force_self_update(self, force_self_update: bool) -> Self {
        Self {
            force_self_update,
            ..self
        }
    }

    pub fn add_proposal(mut self, proposal: Proposal) -> Self {
        self.stage.own_proposals.push(proposal);
        self
    }

    pub fn add_proposals(mut self, proposals: impl IntoIterator<Item = Proposal>) -> Self {
        self.stage.own_proposals.extend(proposals);
        self
    }

    pub fn leaf_node_parameters(self, leaf_node_parameters: LeafNodeParameters) -> Self {
        Self {
            leaf_node_parameters,
            ..self
        }
    }

    pub fn propose_add(mut self, key_package: KeyPackage) -> Self {
        self.stage
            .own_proposals
            .push(Proposal::Add(AddProposal { key_package }));
        self
    }

    pub fn load_psks<Storage: StorageProvider>(
        self,
        storage: &'a Storage,
    ) -> Result<CommitBuilder<LoadedPsks>, PskError> {
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
                    },
                )
            })
            .1)
    }
}

impl<'a> CommitBuilder<'a, LoadedPsks> {
    pub fn construct_proposals<T>(
        self,
        crypto: &impl OpenMlsCrypto,
    ) -> Result<CommitBuilder<'a, ValidatedProposals>, CreateCommitError<T>> {
        let ciphersuite = self.group.ciphersuite();
        let sender = Sender::build_member(self.group.own_leaf_index());
        let (cur_stage, builder) = self.take_stage();
        let psks = cur_stage.psks;

        // put the pending and uniform proposals into a uniform shape, i.e. produce queued
        // proposals from the own proposals by signing them.
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
            .filter(|_| builder.consume_proposal_store)
            .cloned();

        // prepare the iterator for the proposal validation and seletion function. That function
        // assumes that "earlier in the list" means "older", so since our own proposals are
        // newest, we have to put them last.
        let proposal_queue = group_proposal_store_queue.chain(own_proposals);

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

        // TODO: validate proposal list
        //          this is a bit annoying; the easiest way would be to turn all own_proposals into
        //          full QueuedProposals and process them using the existing validation logic.
        //          However. that would require us to pointlessly sign them here, just so they are
        //          in the right format. I think that might even be what we are already doing,
        //          but.. well, it's not great.

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
        if let Sender::Member(sender_index) = &sender {
            // ValSem110
            // ValSem111
            // ValSem112
            builder
                .group
                .public_group
                .validate_update_proposals(&proposal_queue, *sender_index)?;
        }

        // ValSem208
        // ValSem209
        builder
            .group
            .public_group
            .validate_group_context_extensions_proposal(&proposal_queue)?;

        Ok(builder.into_stage(ValidatedProposals {
            proposal_queue,
            contains_own_updates,
            psks,
        }))
    }
}

impl<'a> CommitBuilder<'a, ValidatedProposals> {
    pub fn build<T>(
        self,
        rand: &impl OpenMlsRand,
        crypto: &impl OpenMlsCrypto,
        signer: &impl Signer,
    ) -> Result<CommitBuilder<'a, Complete>, CreateCommitError<T>> {
        let (stage, builder) = self.take_stage();

        let ValidatedProposals {
            proposal_queue,
            contains_own_updates,
            psks,
        } = stage;

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
                || builder.force_self_update
                || !builder.leaf_node_parameters.is_empty()
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
                    &builder.leaf_node_parameters,
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
}
