use thiserror::Error;
use tls_codec::Serialize as _;

use crate::{
    error::LibraryError,
    framing::{mls_content_in::FramedContentBodyIn, DecryptedMessage, PublicMessageIn, Sender},
    group::{
        commit_builder::{CommitBuilder, ExternalCommitInfo, Initial},
        past_secrets::MessageSecretsStore,
        MlsGroup, MlsGroupJoinConfig, MlsGroupState, ProposalStore, PublicGroup, QueuedProposal,
        ValidationError,
    },
    prelude::{
        group_info::VerifiableGroupInfo,
        proposals::{self, ProposalType},
        CreationFromExternalError, CredentialWithKey, ExternalInitProposal, LeafNodeIndex,
        Proposal, ProtocolVersion, RatchetTreeIn, RemoveProposal,
    },
    schedule::{psk::store::ResumptionPskStore, EpochSecrets, InitSecret},
    storage::OpenMlsProvider,
    treesync::LeafNodeParameters,
};

#[derive(Debug, Error)]
pub enum ExternalCommitBuilderError<StorageError> {
    /// See [`LibraryError`] for more details.
    #[error(transparent)]
    LibraryError(#[from] LibraryError),
    /// No ratchet tree available to build initial tree.
    #[error("No ratchet tree available to build initial tree.")]
    MissingRatchetTree,
    /// No external_pub extension available to join group by external commit.
    #[error("No external_pub extension available to join group by external commit.")]
    MissingExternalPub,
    /// We don't support the ciphersuite of the group we are trying to join.
    #[error("We don't support the ciphersuite of the group we are trying to join.")]
    UnsupportedCiphersuite,
    /// This error indicates the public tree is invalid. See
    /// [`CreationFromExternalError`] for more details.
    #[error(transparent)]
    PublicGroupError(#[from] CreationFromExternalError<StorageError>),
    /// An erorr occurred when writing group to storage
    #[error("An error occurred when writing group to storage.")]
    StorageError(StorageError),
    /// Error validating proposals.
    #[error("Error validating proposals: {0}")]
    InvalidProposal(#[from] ValidationError),
}

#[derive(Default)]
pub struct ExternalCommitBuilder {
    proposals: Vec<PublicMessageIn>,
    ratchet_tree: Option<RatchetTreeIn>,
    config: MlsGroupJoinConfig,
    aad: Vec<u8>,
}

impl ExternalCommitBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_proposals(mut self, proposals: Vec<PublicMessageIn>) -> Self {
        self.proposals = proposals;
        self
    }

    pub fn with_ratchet_tree(mut self, ratchet_tree: RatchetTreeIn) -> Self {
        self.ratchet_tree = Some(ratchet_tree);
        self
    }

    pub fn with_config(mut self, config: MlsGroupJoinConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_aad(mut self, aad: Vec<u8>) -> Self {
        self.aad = aad;
        self
    }

    pub fn build_group<Provider: OpenMlsProvider>(
        self,
        provider: &Provider,
        verifiable_group_info: VerifiableGroupInfo,
        credential_with_key: CredentialWithKey,
    ) -> Result<CommitBuilder<Initial, MlsGroup>, ExternalCommitBuilderError<Provider::StorageError>>
    {
        let ExternalCommitBuilder {
            proposals,
            ratchet_tree,
            config,
            aad,
        } = self;

        // Build the ratchet tree

        // Set nodes either from the extension or from the `ratchet_tree`.
        let ratchet_tree = match verifiable_group_info.extensions().ratchet_tree() {
            Some(extension) => extension.ratchet_tree().clone(),
            None => match ratchet_tree {
                Some(ratchet_tree) => ratchet_tree,
                None => return Err(ExternalCommitBuilderError::MissingRatchetTree),
            },
        };

        let (public_group, group_info) = PublicGroup::from_external_internal(
            provider.crypto(),
            ratchet_tree,
            verifiable_group_info,
            ProposalStore::new(),
        )?;
        let group_context = public_group.group_context();

        // Obtain external_pub from GroupInfo extensions.
        let external_pub = group_info
            .extensions()
            .external_pub()
            .ok_or(ExternalCommitBuilderError::MissingExternalPub)?
            .external_pub();

        let (init_secret, kem_output) = InitSecret::from_group_context(
            provider.crypto(),
            group_context,
            external_pub.as_slice(),
        )
        .map_err(|_| ExternalCommitBuilderError::UnsupportedCiphersuite)?;

        // The `EpochSecrets` we create here are essentially zero, with the
        // exception of the `InitSecret`, which is all we need here for the
        // external commit.
        let ciphersuite = group_context.ciphersuite();
        let epoch_secrets =
            EpochSecrets::with_init_secret(provider.crypto(), ciphersuite, init_secret)
                .map_err(LibraryError::unexpected_crypto_error)?;
        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            group_context
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
            public_group.tree_size(),
            // We use a fake own index of 0 here, as we're not going to use the
            // tree for encryption until after the first commit. This issue is
            // tracked in #767.
            LeafNodeIndex::new(0u32),
        );
        let message_secrets_store =
            MessageSecretsStore::new_with_secret(config.max_past_epochs, message_secrets);

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        // Authenticate the proposals as best as we can
        let serialized_context = group_context
            .tls_serialize_detached()
            .map_err(LibraryError::missing_bound_check)?;
        let mut queued_proposals = Vec::new();
        for message in proposals {
            match message.content() {
                FramedContentBodyIn::Proposal(proposal) => {
                    if !matches!(proposal.proposal_type(), ProposalType::SelfRemove)
                        && !matches!(proposal.proposal_type(), ProposalType::PreSharedKey)
                    {
                        continue; // We are only allowed to include SelfRemove and PSK proposals in our external commit.
                    }
                }
                _ => continue, // We ignore messages that are not proposals.
            }
            let decrypted_message = DecryptedMessage::from_inbound_public_message(
                message,
                None,
                serialized_context.clone(),
                provider.crypto(),
                ciphersuite,
            )?;
            let unverified_message = public_group.parse_message(decrypted_message, None)?;
            let (verified_message, _credential) = unverified_message.verify(
                ciphersuite,
                provider.crypto(),
                ProtocolVersion::default(),
            )?;
            let queued_proposal = QueuedProposal::from_authenticated_content(
                ciphersuite,
                provider.crypto(),
                verified_message,
                proposals::ProposalOrRefType::Reference,
            )?;
            let proposal = queued_proposal.proposal();
            if proposal.is_type(ProposalType::PreSharedKey)
                || proposal.is_type(ProposalType::SelfRemove)
            {
                queued_proposals.push(queued_proposal);
            }
        }

        let mut inline_proposals = vec![external_init_proposal];

        // If there is a group member in the group with the same identity as us,
        // commit a remove proposal.
        let signature_key = credential_with_key.signature_key.as_slice();
        if let Some(us) = public_group
            .members()
            .find(|member| member.signature_key == signature_key)
        {
            let remove_proposal = Proposal::Remove(RemoveProposal { removed: us.index });
            inline_proposals.push(remove_proposal);
        };

        let own_leaf_index =
            public_group.leftmost_free_index(inline_proposals.iter(), queued_proposals.iter())?;

        let mut mls_group = MlsGroup {
            mls_group_config: config,
            own_leaf_nodes: vec![],
            aad: vec![],
            group_state: MlsGroupState::Operational,
            public_group,
            group_epoch_secrets,
            own_leaf_index,
            message_secrets_store,
            resumption_psk_store: ResumptionPskStore::new(32),
        };

        for inline_proposal in inline_proposals {
            let queued_proposal = QueuedProposal::from_proposal_and_sender(
                ciphersuite,
                provider.crypto(),
                inline_proposal,
                &Sender::NewMemberCommit,
            )?;
            queued_proposals.push(queued_proposal);
        }

        // Add all proposals to the proposal store.
        let proposal_store = mls_group.proposal_store_mut();
        for queued_proposal in queued_proposals {
            proposal_store.add(queued_proposal);
        }

        let mut commit_builder = CommitBuilder::<'_, Initial, MlsGroup>::new(mls_group);

        commit_builder.stage.force_self_update = true;
        commit_builder.stage.external_commit_info = Some(ExternalCommitInfo {
            credential: credential_with_key.clone(),
            aad,
        });
        let leaf_node_parameters = LeafNodeParameters::builder()
            .with_credential_with_key(credential_with_key)
            .build();
        commit_builder.stage.leaf_node_parameters = leaf_node_parameters;

        Ok(commit_builder)
    }
}
