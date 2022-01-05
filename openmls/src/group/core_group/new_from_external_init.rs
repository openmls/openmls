use crate::{
    ciphersuite::signable::Verifiable,
    group::errors::ExternalCommitError,
    messages::{
        proposals::{ExternalInitProposal, Proposal},
        public_group_state::{PublicGroupState, VerifiablePublicGroupState},
    },
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    CoreGroup,
};
use crate::group::core_group::*;

pub type ExternalCommitResult = (CoreGroup, CreateCommitResult);

impl CoreGroup {
    /// Join a group without the help of an internal member. This function
    /// requires a `PublicGroupState`, as well as the corresponding public tree
    /// `nodes`. After the group state is initialized, this function creates an
    /// `ExternalInit` proposal and commits it along with the given proposals by
    /// reference and by value.
    ///
    /// Returns the new `CoreGroup` object, as well as the `MlsPlaintext`
    /// containing the commit.
    pub fn join_by_external_commit(
        backend: &impl OpenMlsCryptoProvider,
        params: CreateCommitParams,
        tree_option: Option<&[Option<Node>]>,
        verifiable_public_group_state: VerifiablePublicGroupState,
    ) -> Result<ExternalCommitResult, CoreGroupError> {
        let ciphersuite = Config::ciphersuite(verifiable_public_group_state.ciphersuite())?;
        if !Config::supported_versions().contains(&verifiable_public_group_state.version()) {
            return Err(ExternalCommitError::UnsupportedMlsVersion.into());
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
                None => return Err(ExternalCommitError::MissingRatchetTree.into()),
            },
        };

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the PGS, since we need to find the Credential to verify the
        // signature against.
        let treesync = TreeSync::from_nodes_without_leaf(backend, ciphersuite, nodes)?;

        if treesync.tree_hash() != verifiable_public_group_state.tree_hash() {
            return Err(ExternalCommitError::TreeHashMismatch.into());
        }

        // FIXME #680: Validation of external commits

        let pgs_signer_leaf = treesync.leaf(verifiable_public_group_state.signer_index())?;
        let pgs_signer_credential = pgs_signer_leaf
            .ok_or(ExternalCommitError::UnknownSender)?
            .key_package()
            .credential();
        let pgs: PublicGroupState =
            verifiable_public_group_state.verify(backend, pgs_signer_credential)?;

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
        let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

        // Prepare interim transcript hash
        let group = CoreGroup {
            ciphersuite,
            group_context,
            tree: treesync,
            interim_transcript_hash: pgs.interim_transcript_hash.into(),
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            mls_version: pgs.version,
            group_epoch_secrets,
            message_secrets_store,
        };

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        // FIXME #682: Check if old self is in the group. If that is the case,
        // add a remove proposal.
        let inline_proposals = vec![external_init_proposal];

        let params = CreateCommitParams::builder()
            .framing_parameters(*params.framing_parameters())
            .credential_bundle(params.credential_bundle())
            .proposal_store(params.proposal_store())
            .inline_proposals(inline_proposals)
            .commit_type(CommitType::External)
            .build();

        // Immediately create the commit to add ourselves to the group.
        let create_commit_result = group
            .create_commit(params, backend)
            .map_err(|_| ExternalCommitError::CommitError)?;

        Ok((group, create_commit_result))
    }
}
