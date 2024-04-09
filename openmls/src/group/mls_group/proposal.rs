use core_group::create_commit_params::CreateCommitParams;
use openmls_traits::{
    key_store::OpenMlsKeyStore, signatures::Signer, types::Ciphersuite, OpenMlsProvider,
};

use super::{
    core_group, errors::{ProposalError, ProposeAddMemberError, ProposeRemoveMemberError}, CreateGroupContextExtProposalError, GroupContextExtensionProposal, GroupContextExtensionsProposalValidationError, MlsGroup, MlsGroupState, PendingCommitState, Proposal
};
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::Credential,
    extensions::Extensions,
    framing::MlsMessageOut,
    group::{errors::CreateAddProposalError, GroupId, QueuedProposal},
    key_packages::KeyPackage,
    messages::{group_info::GroupInfo, proposals::ProposalOrRefType},
    prelude::LibraryError,
    schedule::PreSharedKeyId,
    treesync::LeafNode,
    versions::ProtocolVersion,
};

/// Helper for building a proposal based on the raw values.
#[derive(Debug, PartialEq, Clone)]
pub enum Propose {
    /// An add proposal requires a key package of the addee.
    Add(KeyPackage),

    /// An update proposal requires a new leaf node.
    Update(Option<LeafNode>),

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
}

macro_rules! impl_propose_fun {
    ($name:ident, $value_ty:ty, $group_fun:ident, $ref_or_value:expr) => {
        // TODO: Documentation wrong.
        /// Creates proposals to add an external PSK to the key schedule.
        ///
        /// Returns an error if there is a pending commit.
        pub fn $name<KeyStore: OpenMlsKeyStore>(
            &mut self,
            provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
            signer: &impl Signer,
            value: $value_ty,
        ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<KeyStore::Error>> {
            self.is_operational()?;

            let proposal = self
                .group
                .$group_fun(self.framing_parameters(), value, signer)?;

            let queued_proposal = QueuedProposal::from_authenticated_content(
                self.ciphersuite(),
                provider.crypto(),
                proposal.clone(),
                $ref_or_value,
            )?;
            let proposal_ref = queued_proposal.proposal_reference();
            log::trace!("Storing proposal in queue {:?}", queued_proposal);
            self.proposal_store.add(queued_proposal);

            let mls_message = self.content_to_mls_message(proposal, provider)?;

            // Since the state of the group might be changed, arm the state flag
            self.flag_state_change();

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

    /// Generate a proposal
    pub fn propose<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        propose: Propose,
        ref_or_value: ProposalOrRefType,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<KeyStore::Error>> {
        match propose {
            Propose::Add(key_package) => match ref_or_value {
                ProposalOrRefType::Proposal => {
                    self.propose_add_member_by_value(provider, signer, key_package)
                }
                ProposalOrRefType::Reference => self
                    .propose_add_member(provider, signer, &key_package)
                    .map_err(|e| e.into()),
            },

            Propose::Update(leaf_node) => match ref_or_value {
                ProposalOrRefType::Proposal => self
                    .propose_self_update_by_value(provider, signer, leaf_node)
                    .map_err(|e| e.into()),
                ProposalOrRefType::Reference => self
                    .propose_self_update(provider, signer, leaf_node)
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
        }
    }

    /// Creates proposals to add members to the group.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_add_member(
        &mut self,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        key_package: &KeyPackage,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeAddMemberError> {
        self.is_operational()?;

        let add_proposal = self
            .group
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
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(add_proposal, provider)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }

    /// Creates proposals to remove members from the group.
    /// The `member` has to be the member's leaf index.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_remove_member(
        &mut self,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        member: LeafNodeIndex,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeRemoveMemberError> {
        self.is_operational()?;

        let remove_proposal = self
            .group
            .create_remove_proposal(self.framing_parameters(), member, signer)
            .map_err(|_| ProposeRemoveMemberError::UnknownMember)?;

        let proposal = QueuedProposal::from_authenticated_content_by_ref(
            self.ciphersuite(),
            provider.crypto(),
            remove_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference();
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(remove_proposal, provider)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }

    /// Creates proposals to remove members from the group.
    /// The `member` has to be the member's credential.
    ///
    /// Returns an error if there is a pending commit.
    pub fn propose_remove_member_by_credential(
        &mut self,
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        member: &Credential,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposeRemoveMemberError> {
        // Find the user for the credential first.
        let member_index = self
            .group
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
    pub fn propose_remove_member_by_credential_by_value<KeyStore: OpenMlsKeyStore>(
        &mut self,
        provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        member: &Credential,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<KeyStore::Error>> {
        // Find the user for the credential first.
        let member_index = self
            .group
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

    pub fn propose_group_context_extensions(
        &mut self,
        provider: &impl OpenMlsProvider,
        extensions: Extensions,
        signer: &impl Signer,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<()>> {
        self.is_operational()?;

        let proposal = self.group.create_group_context_ext_proposal(
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
        self.proposal_store.add(queued_proposal);

        let mls_message = self.content_to_mls_message(proposal, provider)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }

    pub fn update_group_context_extensions(
        &mut self,
        provider: &impl OpenMlsProvider,
        extensions: Extensions,
        signer: &impl Signer,
    ) -> Result<(MlsMessageOut, MlsMessageOut, Option<GroupInfo>), CreateGroupContextExtProposalError> 
    {
        self.is_operational()?;

        // if key_packages.is_empty() {
        //     return Err(CreateGroupContextExtProposalError::EmptyInput(EmptyInputError::AddMembers));
        // }

        // Create inline add proposals from key packages
        let mut inline_proposals = vec![];
        inline_proposals.push(Proposal::GroupContextExtensions(GroupContextExtensionProposal {
            extensions,
        }));

        let params = CreateCommitParams::builder()
            .framing_parameters(self.framing_parameters())
            .proposal_store(&self.proposal_store)
            .inline_proposals(inline_proposals)
            .build();
        let create_commit_result = self.group.create_commit(params, provider, signer).unwrap();
        let welcome = match create_commit_result.welcome_option {
            Some(welcome) => welcome,
            None => {
                return Err(LibraryError::custom("No secrets to generate commit message.").into())
            }
        };
        let mls_messages = self.content_to_mls_message(create_commit_result.commit, provider)?;
        self.group_state = MlsGroupState::PendingCommit(Box::new(PendingCommitState::Member(
            create_commit_result.staged_commit,
        )));

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((
            mls_messages,
            MlsMessageOut::from_welcome(welcome, self.group.version()),
            create_commit_result.group_info,
        ))
    }
}
