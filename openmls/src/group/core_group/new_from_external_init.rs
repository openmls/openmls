use crate::{
    ciphersuite::signable::Verifiable,
    credentials::CredentialBundle,
    framing::plaintext::MlsPlaintext,
    group::errors::ExternalInitError,
    messages::{
        proposals::{ExternalInitProposal, Proposal},
        public_group_state::{PublicGroupState, VerifiablePublicGroupState},
    },
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    proposals::{ProposalStore, QueuedProposal},
    CoreGroup,
};
use crate::group::core_group::*;

pub type ExternalInitResult = (CoreGroup, CreateCommitResult);

impl CoreGroup {
    /// Join a group without the help of an internal member. This function
    /// requires a `PublicGroupState`, as well as the corresponding public tree
    /// `nodes`. After the group state is initialized, this function creates an
    /// `ExternalInit` proposal and commits it along with the given proposals by
    /// reference and by value.
    ///
    /// Returns the new `CoreGroup` object, as well as the `MlsPlaintext`
    /// containing the commit.
    pub fn new_from_external_init(
        backend: &impl OpenMlsCryptoProvider,
        framing_parameters: FramingParameters,
        tree_option: Option<&[Option<Node>]>,
        credential_bundle: &CredentialBundle,
        proposals_by_reference: &[MlsPlaintext],
        proposals_by_value: &[Proposal],
        verifiable_public_group_state: VerifiablePublicGroupState,
    ) -> Result<ExternalInitResult, CoreGroupError> {
        let ciphersuite = Config::ciphersuite(verifiable_public_group_state.ciphersuite())?;
        if !Config::supported_versions().contains(&verifiable_public_group_state.version()) {
            Err(ExternalInitError::UnsupportedMlsVersion)?;
        }

        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let extension_tree_option =
            try_nodes_from_extensions(verifiable_public_group_state.other_extensions())?;
        let (nodes, enable_ratchet_tree_extension) = match extension_tree_option {
            Some(ref nodes) => (nodes, true),
            None => match tree_option.as_ref() {
                Some(n) => (n, false),
                None => Err(ExternalInitError::MissingRatchetTree)?,
            },
        };

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the PGS, since we need to find the Credential to verify the
        // signature against.
        let treesync = TreeSync::from_nodes_without_leaf(backend, ciphersuite, nodes)?;

        if treesync.tree_hash() != verifiable_public_group_state.tree_hash() {
            Err(ExternalInitError::TreeHashMismatch)?;
        }

        let pgs_signer_leaf = treesync.leaf(verifiable_public_group_state.signer_index())?;
        let pgs_signer_credential = pgs_signer_leaf
            .ok_or(ExternalInitError::UnknownSender)?
            .key_package()
            .credential();
        let pgs: PublicGroupState = verifiable_public_group_state
            .verify(backend, pgs_signer_credential)
            .map_err(|_| ExternalInitError::InvalidPublicGroupStateSignature)?;

        let (init_secret, kem_output) = InitSecret::from_public_group_state(backend, &pgs)?;

        // We create the GroupContext with the values from the PGS, even though
        // we already changed the tree by adding our own leaf, thus invalidating
        // the tree hash.
        let group_context = GroupContext::new(
            pgs.group_id,
            pgs.epoch,
            pgs.tree_hash.as_slice().to_vec(),
            pgs.confirmed_transcript_hash.into(),
            pgs.group_context_extensions.as_slice(),
        )?;

        // The `EpochSecrets` we create here are essentially zero, with the
        // exception of the `InitSecret`, which is all we need here for the
        // external commit.
        let epoch_secrets = EpochSecrets::with_init_secret(backend, init_secret)?;
        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            group_context.tls_serialize_detached()?,
            treesync.leaf_count()?,
        );

        // Prepare interim transcript hash
        let group = CoreGroup {
            ciphersuite,
            group_context,
            tree: treesync,
            interim_transcript_hash: pgs.interim_transcript_hash.into(),
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            mls_version: pgs.version,
            group_epoch_secrets,
            message_secrets,
        };

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        let mut proposal_store = ProposalStore::default();
        for proposal in proposals_by_reference {
            let staged_proposal =
                QueuedProposal::from_mls_plaintext(ciphersuite, backend, proposal.clone())?;
            proposal_store.add(staged_proposal)
        }

        let mut inline_proposals = proposals_by_value.to_vec();
        inline_proposals.push(external_init_proposal);

        let params = CreateCommitParams::builder()
            .framing_parameters(framing_parameters)
            .credential_bundle(credential_bundle)
            .proposal_store(&proposal_store)
            .inline_proposals(inline_proposals)
            .commit_type(CommitType::External)
            .build();

        // Immediately create the commit to add ourselves to the group.
        let create_commit_result = group
            .create_commit(params, backend)
            .map_err(|_| ExternalInitError::CommitError)?;

        Ok((group, create_commit_result))
    }
}
