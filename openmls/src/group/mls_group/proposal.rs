use openmls_traits::{signatures::Signer, storage::StorageProvider as _, types::Ciphersuite};

use super::{
    create_commit::CreateCommitParams,
    errors::{ProposalError, ProposeAddMemberError, ProposeRemoveMemberError, RemoveProposalError},
    AddProposal, CreateGroupContextExtProposalError, CustomProposal, FramingParameters,
    GroupContextExtensionProposal, MlsGroup, MlsGroupState, PendingCommitState,
    PreSharedKeyProposal, Proposal, QueuedProposal, RemoveProposal, UpdateProposal,
};
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::Credential,
    extensions::Extensions,
    framing::{mls_auth_content::AuthenticatedContent, MlsMessageOut},
    group::{errors::CreateAddProposalError, GroupId, ValidationError},
    key_packages::KeyPackage,
    messages::{group_info::GroupInfo, proposals::ProposalOrRefType},
    prelude::LibraryError,
    schedule::PreSharedKeyId,
    storage::{OpenMlsProvider, StorageProvider},
    treesync::{LeafNode, LeafNodeParameters},
    versions::ProtocolVersion,
};

/// Helper for building a proposal based on the raw values.
#[derive(Debug, PartialEq, Clone)]
pub enum Propose {
    /// An add proposal requires a key package of the addee.
    Add(KeyPackage),

    /// An update proposal requires a new leaf node.
    Update(LeafNodeParameters),

    /// A remove proposal consists of the leaf index of the leaf to be removed.
    Remove(u32),

    /// A remove proposal for the leaf with the credential.
    RemoveCredential(Credential),

    /// A PSK proposal gets a pre shared key id.
    PreSharedKey(PreSharedKeyId),

    /// A re-init proposal gets the [`GroupId`], [`ProtocolVersion`], [`Ciphersuite`], and [`Extensions`].
    ReInit {
        group_id: GroupId,
        version: ProtocolVersion,
        ciphersuite: Ciphersuite,
        extensions: Extensions,
    },

    /// An external init proposal gets the raw bytes from the KEM output.
    ExternalInit(Vec<u8>),

    /// Propose adding new group context extensions.
    GroupContextExtensions(Extensions),

    /// A custom proposal with semantics to be implemented by the application.
    Custom(CustomProposal),
}

macro_rules! impl_propose_fun {
    ($name:ident, $value_ty:ty, $group_fun:ident, $ref_or_value:expr) => {
        // TODO: Documentation wrong.
        /// Creates proposals to add an external PSK to the key schedule.
        ///
        /// Returns an error if there is a pending commit.
        pub fn $name<Provider: OpenMlsProvider>(
            &mut self,
            provider: &Provider,
            signer: &impl Signer,
            value: $value_ty,
        ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<Provider::StorageError>> {
            self.is_operational()?;

            let proposal = self.$group_fun(self.framing_parameters(), value, signer)?;

            let queued_proposal = QueuedProposal::from_authenticated_content(
                self.ciphersuite(),
                provider.crypto(),
                proposal.clone(),
                $ref_or_value,
            )?;
            let proposal_ref = queued_proposal.proposal_reference();

            log::trace!("Storing proposal in queue {:?}", queued_proposal);
            provider
                .storage()
                .queue_proposal(self.group_id(), &proposal_ref, &queued_proposal)
                .map_err(ProposalError::StorageError)?;
            self.proposal_store_mut().add(queued_proposal);

            let mls_message = self.content_to_mls_message(proposal, provider)?;

            self.reset_aad();
            Ok((mls_message, proposal_ref))
        }
    };
}

impl MlsGroup {
    impl_propose_fun!(
        propose_add_member_by_value,
        KeyPackage,
        create_add_proposal,
        ProposalOrRefType::Proposal
    );

    impl_propose_fun!(
        propose_remove_member_by_value,
        LeafNodeIndex,
        create_remove_proposal,
        ProposalOrRefType::Proposal
    );

    impl_propose_fun!(
        propose_external_psk,
        PreSharedKeyId,
        create_presharedkey_proposal,
        ProposalOrRefType::Reference
    );

    impl_propose_fun!(
        propose_external_psk_by_value,
        PreSharedKeyId,
        create_presharedkey_proposal,
        ProposalOrRefType::Proposal
    );

    impl_propose_fun!(
        propose_custom_proposal_by_value,
        CustomProposal,
        create_custom_proposal,
        ProposalOrRefType::Proposal
    );

    impl_propose_fun!(
        propose_custom_proposal_by_reference,
        CustomProposal,
        create_custom_proposal,
        ProposalOrRefType::Reference
    );

    /// Generate a proposal
    pub fn propose<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        propose: Propose,
        ref_or_value: ProposalOrRefType,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<Provider::StorageError>> {
        match propose {
            Propose::Add(key_package) => match ref_or_value {
                ProposalOrRefType::Proposal => {
                    self.propose_add_member_by_value(provider, signer, key_package)
                }
                ProposalOrRefType::Reference => self
                    .propose_add_member(provider, signer, &key_package)
                    .map_err(|e| e.into()),
            },

            Propose::Update(leaf_node_parameters) => match ref_or_value {
                ProposalOrRefType::Proposal => self
                    .propose_self_update(provider, signer, leaf_node_parameters)
                    .map_err(|e| e.into()),
                ProposalOrRefType::Reference => self
                    .propose_self_update(provider, signer, leaf_node_parameters)
                    .map_err(|e| e.into()),
            },

            Propose::Remove(leaf_index) => match ref_or_value {
                ProposalOrRefType::Proposal => self.propose_remove_member_by_value(
                    provider,
                    signer,
                    LeafNodeIndex::new(leaf_index),
                ),
                ProposalOrRefType::Reference => self
                    .propose_remove_member(provider, signer, LeafNodeIndex::new(leaf_index))
                    .map_err(|e| e.into()),
            },

            Propose::RemoveCredential(credential) => match ref_or_value {
                ProposalOrRefType::Proposal => {
                    self.propose_remove_member_by_credential_by_value(provider, signer, &credential)
                }
                ProposalOrRefType::Reference => self
                    .propose_remove_member_by_credential(provider, signer, &credential)
                    .map_err(|e| e.into()),
            },
            Propose::PreSharedKey(psk_id) => match psk_id.psk() {
                crate::schedule::Psk::External(_) => match ref_or_value {
                    ProposalOrRefType::Proposal => {
                        self.propose_external_psk_by_value(provider, signer, psk_id)
                    }
                    ProposalOrRefType::Reference => {
                        self.propose_external_psk(provider, signer, psk_id)
                    }
                },
                crate::schedule::Psk::Resumption(_) => Err(ProposalError::LibraryError(
                    LibraryError::custom("Invalid PSk argument"),
                )),
            },
            Propose::ReInit {
                group_id: _,
                version: _,
                ciphersuite: _,
                extensions: _,
            } => Err(ProposalError::LibraryError(LibraryError::custom(
                "Unsupported proposal type ReInit",
            ))),
            Propose::ExternalInit(_) => Err(ProposalError::LibraryError(LibraryError::custom(
                "Unsupported proposal type ExternalInit",
            ))),
            Propose::GroupContextExtensions(_) => Err(ProposalError::LibraryError(
                LibraryError::custom("Unsupported proposal type GroupContextExtensions"),
            )),
            Propose::Custom(custom_proposal) => match ref_or_value {
                ProposalOrRefType::Proposal => {
                    self.propose_custom_proposal_by_value(provider, signer, custom_proposal)
                }
                ProposalOrRefType::Reference => {
                    self.propose_custom_proposal_by_reference(provider, signer, custom_proposal)
                }
            },
        }
    }

    /// Creates proposals to add members to the group.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_add_member<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        key_package: &KeyPackage,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeAddMemberError<Provider::StorageError>> {
        self.is_operational()?;

        let add_proposal = self
            .create_add_proposal(self.framing_parameters(), key_package.clone(), signer)
            .map_err(|e| match e {
                CreateAddProposalError::LibraryError(e) => e.into(),
                CreateAddProposalError::LeafNodeValidation(error) => {
                    ProposeAddMemberError::LeafNodeValidation(error)
                }
            })?;

        let proposal = QueuedProposal::from_authenticated_content_by_ref(
            self.ciphersuite(),
            provider.crypto(),
            add_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference();
        provider
            .storage()
            .queue_proposal(self.group_id(), &proposal_ref, &proposal)
            .map_err(ProposeAddMemberError::StorageError)?;
        self.proposal_store_mut().add(proposal);

        let mls_message = self.content_to_mls_message(add_proposal, provider)?;

        self.reset_aad();
        Ok((mls_message, proposal_ref))
    }

    /// Creates proposals to remove members from the group.
    /// The `member` has to be the member's leaf index.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_remove_member<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        member: LeafNodeIndex,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeRemoveMemberError<Provider::StorageError>>
    {
        self.is_operational()?;

        let remove_proposal = self
            .create_remove_proposal(self.framing_parameters(), member, signer)
            .map_err(|_| ProposeRemoveMemberError::UnknownMember)?;

        let proposal = QueuedProposal::from_authenticated_content_by_ref(
            self.ciphersuite(),
            provider.crypto(),
            remove_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference();
        provider
            .storage()
            .queue_proposal(self.group_id(), &proposal_ref, &proposal)
            .map_err(ProposeRemoveMemberError::StorageError)?;
        self.proposal_store_mut().add(proposal);

        let mls_message = self.content_to_mls_message(remove_proposal, provider)?;

        self.reset_aad();
        Ok((mls_message, proposal_ref))
    }

    /// Creates proposals to remove members from the group.
    /// The `member` has to be the member's credential.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_remove_member_by_credential<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        member: &Credential,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeRemoveMemberError<Provider::StorageError>>
    {
        // Find the user for the credential first.
        let member_index = self
            .public_group()
            .members()
            .find(|m| &m.credential == member)
            .map(|m| m.index);

        if let Some(member_index) = member_index {
            self.propose_remove_member(provider, signer, member_index)
        } else {
            Err(ProposeRemoveMemberError::UnknownMember)
        }
    }

    /// Creates proposals to remove members from the group.
    /// The `member` has to be the member's credential.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_remove_member_by_credential_by_value<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        signer: &impl Signer,
        member: &Credential,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<Provider::StorageError>> {
        // Find the user for the credential first.
        let member_index = self
            .public_group()
            .members()
            .find(|m| &m.credential == member)
            .map(|m| m.index);

        if let Some(member_index) = member_index {
            self.propose_remove_member_by_value(provider, signer, member_index)
        } else {
            Err(ProposalError::ProposeRemoveMemberError(
                ProposeRemoveMemberError::UnknownMember,
            ))
        }
    }

    /// Creates a proposals with a new set of `extensions` for the group context.
    ///
    /// Returns an error when the group does not support all the required capabilities
    /// in the new `extensions`.
    pub fn propose_group_context_extensions<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        extensions: Extensions,
        signer: &impl Signer,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<Provider::StorageError>> {
        self.is_operational()?;

        let proposal = self.create_group_context_ext_proposal::<Provider>(
            self.framing_parameters(),
            extensions,
            signer,
        )?;

        let queued_proposal = QueuedProposal::from_authenticated_content_by_ref(
            self.ciphersuite(),
            provider.crypto(),
            proposal.clone(),
        )?;

        let proposal_ref = queued_proposal.proposal_reference();
        provider
            .storage()
            .queue_proposal(self.group_id(), &proposal_ref, &queued_proposal)
            .map_err(ProposalError::StorageError)?;
        self.proposal_store_mut().add(queued_proposal);

        let mls_message = self.content_to_mls_message(proposal, provider)?;

        self.reset_aad();
        Ok((mls_message, proposal_ref))
    }

    /// Updates Group Context Extensions
    ///
    /// Commits to the Group Context Extension inline proposal using the [`Extensions`]
    ///
    /// Returns an error when the group does not support all the required capabilities
    /// in the new `extensions` or if there is a pending commit.
    //// FIXME: #1217
    #[allow(clippy::type_complexity)]
    pub fn update_group_context_extensions<Provider: OpenMlsProvider>(
        &mut self,
        provider: &Provider,
        extensions: Extensions,
        signer: &impl Signer,
    ) -> Result<
        (MlsMessageOut, Option<MlsMessageOut>, Option<GroupInfo>),
        CreateGroupContextExtProposalError<Provider::StorageError>,
    > {
        self.is_operational()?;

        // Create inline group context extension proposals
        let inline_proposals = vec![Proposal::GroupContextExtensions(
            GroupContextExtensionProposal::new(extensions),
        )];

        // Create Commit over all proposals
        let params = CreateCommitParams::builder()
            .regular_commit()
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.create_commit(params, provider, signer)?;

        let mls_messages = self.content_to_mls_message(create_commit_result.commit, provider)?;

        // Set the current group state to [`MlsGroupState::PendingCommit`],
        // storing the current [`StagedCommit`] from the commit results
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        provider
            .storage()
            .write_group_state(self.group_id(), &self.group_state)
            .map_err(CreateGroupContextExtProposalError::StorageError)?;

        self.reset_aad();
        Ok((
            mls_messages,
            create_commit_result
                .welcome_option
                .map(|w| MlsMessageOut::from_welcome(w, self.version())),
            create_commit_result.group_info,
        ))
    }

    /// Removes a specific proposal from the store.
    pub fn remove_pending_proposal<Storage: StorageProvider>(
        &mut self,
        storage: &Storage,
        proposal_ref: &ProposalRef,
    ) -> Result<(), RemoveProposalError<Storage::Error>> {
        storage
            .remove_proposal(self.group_id(), proposal_ref)
            .map_err(RemoveProposalError::Storage)?;
        self.proposal_store_mut()
            .remove(proposal_ref)
            .ok_or(RemoveProposalError::ProposalNotFound)
    }

    // === Create handshake messages ===

    // 12.1.1. Add
    // struct {
    //     KeyPackage key_package;
    // } Add;
    pub(crate) fn create_add_proposal(
        &self,
        framing_parameters: FramingParameters,
        joiner_key_package: KeyPackage,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, CreateAddProposalError> {
        if let Some(required_capabilities) = self.required_capabilities() {
            joiner_key_package
                .leaf_node()
                .capabilities()
                .supports_required_capabilities(required_capabilities)?;
        }
        let add_proposal = AddProposal {
            key_package: joiner_key_package,
        };
        let proposal = Proposal::Add(add_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
        .map_err(|e| e.into())
    }

    // 12.1.2. Update
    // struct {
    //     LeafNode leaf_node;
    // } Update;
    pub(crate) fn create_update_proposal(
        &self,
        framing_parameters: FramingParameters,
        // XXX: There's no need to own this. The [`UpdateProposal`] should
        //      operate on a reference to make this more efficient.
        leaf_node: LeafNode,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, LibraryError> {
        let update_proposal = UpdateProposal { leaf_node };
        let proposal = Proposal::Update(update_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
    }

    // 12.1.3. Remove
    // struct {
    //     uint32 removed;
    // } Remove;
    pub(crate) fn create_remove_proposal(
        &self,
        framing_parameters: FramingParameters,
        removed: LeafNodeIndex,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, ValidationError> {
        if self.public_group().leaf(removed).is_none() {
            return Err(ValidationError::UnknownMember);
        }
        let remove_proposal = RemoveProposal { removed };
        let proposal = Proposal::Remove(remove_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
        .map_err(ValidationError::LibraryError)
    }

    // 12.1.4. PreSharedKey
    // struct {
    //     PreSharedKeyID psk;
    // } PreSharedKey;
    // TODO: #751
    pub(crate) fn create_presharedkey_proposal(
        &self,
        framing_parameters: FramingParameters,
        psk: PreSharedKeyId,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, LibraryError> {
        let presharedkey_proposal = PreSharedKeyProposal::new(psk);
        let proposal = Proposal::PreSharedKey(presharedkey_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
    }

    pub(crate) fn create_custom_proposal(
        &self,
        framing_parameters: FramingParameters,
        custom_proposal: CustomProposal,
        signer: &impl Signer,
    ) -> Result<AuthenticatedContent, LibraryError> {
        let proposal = Proposal::Custom(custom_proposal);
        AuthenticatedContent::member_proposal(
            framing_parameters,
            self.own_leaf_index(),
            proposal,
            self.context(),
            signer,
        )
    }
}
