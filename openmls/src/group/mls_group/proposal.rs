use openmls_traits::{
    key_store::OpenMlsKeyStore, signatures::Signer, types::Ciphersuite, OpenMlsCryptoProvider,
};

use super::{
    errors::{ProposalError, ProposeAddMemberError, ProposeRemoveMemberError},
    MlsGroup,
};
use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::hash_ref::ProposalRef,
    credentials::Credential,
    extensions::Extensions,
    framing::MlsMessageOut,
    group::{errors::CreateAddProposalError, GroupId, QueuedProposal},
    key_packages::KeyPackage,
    messages::proposals::ProposalOrRefType,
    prelude::{LibraryError, ProposeGroupContextExtensionsError},
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
            backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
            signer: &impl Signer,
            value: $value_ty,
        ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<KeyStore::Error>> {
            self.is_operational()?;

            let proposal = self
                .group
                .$group_fun(self.framing_parameters(), value, signer)?;

            let queued_proposal = QueuedProposal::from_authenticated_content(
                self.ciphersuite(),
                backend,
                proposal.clone(),
                $ref_or_value,
            )?;
            let proposal_ref = queued_proposal.proposal_reference();
            log::trace!("Storing proposal in queue {:?}", queued_proposal);
            self.proposal_store.add(queued_proposal);

            let mls_message = self.content_to_mls_message(proposal, backend)?;

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
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
        signer: &impl Signer,
        propose: Propose,
        ref_or_value: ProposalOrRefType,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<KeyStore::Error>> {
        match propose {
            Propose::Add(key_package) => match ref_or_value {
                ProposalOrRefType::Proposal => {
                    self.propose_add_member_by_value(backend, signer, key_package)
                }
                ProposalOrRefType::Reference => self
                    .propose_add_member(backend, signer, &key_package)
                    .map_err(|e| e.into()),
            },

            Propose::Update(leaf_node) => match ref_or_value {
                ProposalOrRefType::Proposal => self
                    .propose_self_update_by_value(backend, signer, leaf_node)
                    .map_err(|e| e.into()),
                ProposalOrRefType::Reference => self
                    .propose_self_update(backend, signer, leaf_node)
                    .map_err(|e| e.into()),
            },

            Propose::Remove(leaf_index) => match ref_or_value {
                ProposalOrRefType::Proposal => self.propose_remove_member_by_value(
                    backend,
                    signer,
                    LeafNodeIndex::new(leaf_index),
                ),
                ProposalOrRefType::Reference => self
                    .propose_remove_member(backend, signer, LeafNodeIndex::new(leaf_index))
                    .map_err(|e| e.into()),
            },

            Propose::RemoveCredential(credential) => match ref_or_value {
                ProposalOrRefType::Proposal => {
                    self.propose_remove_member_by_credential_by_value(backend, signer, &credential)
                }
                ProposalOrRefType::Reference => self
                    .propose_remove_member_by_credential(backend, signer, &credential)
                    .map_err(|e| e.into()),
            },
            Propose::PreSharedKey(psk_id) => match psk_id.psk() {
                crate::schedule::Psk::External(_) => match ref_or_value {
                    ProposalOrRefType::Proposal => {
                        self.propose_external_psk_by_value(backend, signer, psk_id)
                    }
                    ProposalOrRefType::Reference => {
                        self.propose_external_psk(backend, signer, psk_id)
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
        backend: &impl OpenMlsCryptoProvider,
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
            backend,
            add_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference();
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(add_proposal, backend)?;

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
        backend: &impl OpenMlsCryptoProvider,
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
            backend,
            remove_proposal.clone(),
        )?;
        let proposal_ref = proposal.proposal_reference();
        self.proposal_store.add(proposal);

        let mls_message = self.content_to_mls_message(remove_proposal, backend)?;

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
        backend: &impl OpenMlsCryptoProvider,
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
            self.propose_remove_member(backend, signer, member_index)
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
        backend: &impl OpenMlsCryptoProvider<KeyStoreProvider = KeyStore>,
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
            self.propose_remove_member_by_value(backend, signer, member_index)
        } else {
            Err(ProposalError::ProposeRemoveMemberError(
                ProposeRemoveMemberError::UnknownMember,
            ))
        }
    }

    pub fn propose_group_context_extensions(
        &mut self,
        backend: &impl OpenMlsCryptoProvider,
        extensions: Extensions,
        signer: &impl Signer,
    ) -> Result<(MlsMessageOut, ProposalRef), ProposalError<()>> {
        self.is_operational()?;

        let proposal = self
            .group
            .create_group_context_ext_proposal(self.framing_parameters(), extensions, signer)
            .map_err(|_| ProposeGroupContextExtensionsError::Something)?;

        let queued_proposal = QueuedProposal::from_authenticated_content_by_ref(
            self.ciphersuite(),
            backend,
            proposal.clone(),
        )?;

        let proposal_ref = queued_proposal.proposal_reference();
        self.proposal_store.add(queued_proposal);

        let mls_message = self.content_to_mls_message(proposal, backend)?;

        // Since the state of the group might be changed, arm the state flag
        self.flag_state_change();

        Ok((mls_message, proposal_ref))
    }
}
