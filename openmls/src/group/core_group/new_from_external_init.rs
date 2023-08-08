use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    group::{
        core_group::create_commit_params::{CommitType, CreateCommitParams},
        errors::ExternalCommitError,
    },
    messages::proposals::{ExternalInitProposal, Proposal},
};

use super::CoreGroup;
use crate::group::core_group::*;

pub(crate) type ExternalCommitResult = (CoreGroup, CreateCommitResult);

impl CoreGroup {
    /// Join a group without the help of an internal member. This function
    /// requires a [GroupInfo], as well as the corresponding public tree
    /// `nodes`. After the group state is initialized, this function creates an
    /// `ExternalInit` proposal and commits it along with the given proposals by
    /// reference and by value.
    ///
    /// Returns the new `CoreGroup` object, as well as the `PublicMessage`
    /// containing the commit.
    ///
    /// Note: If there is a group member in the group with the same identity as us,
    /// this will create a remove proposal.
    pub(crate) fn join_by_external_commit(
        provider: &impl OpenMlsProvider,
        signer: &impl Signer,
        mut params: CreateCommitParams,
        ratchet_tree: Option<RatchetTreeIn>,
        verifiable_group_info: VerifiableGroupInfo,
    ) -> Result<ExternalCommitResult, ExternalCommitError> {
        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let (ratchet_tree, enable_ratchet_tree_extension) =
            match verifiable_group_info.extensions().ratchet_tree() {
                Some(extension) => (extension.ratchet_tree().clone(), true),
                None => match ratchet_tree {
                    Some(ratchet_tree) => (ratchet_tree, false),
                    None => return Err(ExternalCommitError::MissingRatchetTree),
                },
            };

        let (public_group, group_info) = PublicGroup::from_external(
            provider.crypto(),
            ratchet_tree,
            verifiable_group_info,
            // Existing proposals are discarded when joining by external commit.
            ProposalStore::new(),
        )?;
        let group_context = public_group.group_context();

        // Obtain external_pub from GroupInfo extensions.
        let external_pub = group_info
            .extensions()
            .external_pub()
            .ok_or(ExternalCommitError::MissingExternalPub)?
            .external_pub();

        let (init_secret, kem_output) = InitSecret::from_group_context(
            provider.crypto(),
            group_context,
            external_pub.as_slice(),
        )
        .map_err(|_| ExternalCommitError::UnsupportedCiphersuite)?;

        // The `EpochSecrets` we create here are essentially zero, with the
        // exception of the `InitSecret`, which is all we need here for the
        // external commit.
        let epoch_secrets = EpochSecrets::with_init_secret(provider.crypto(), init_secret)
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
        let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        let mut inline_proposals = vec![external_init_proposal];

        // If there is a group member in the group with the same identity as us,
        // commit a remove proposal.
        let params_credential_with_key = params
            .take_credential_with_key()
            .ok_or(ExternalCommitError::MissingCredential)?;
        if let Some(us) = public_group.members().find(|member| {
            member.signature_key == params_credential_with_key.signature_key.as_slice()
        }) {
            let remove_proposal = Proposal::Remove(RemoveProposal { removed: us.index });
            inline_proposals.push(remove_proposal);
        };

        let own_leaf_index = public_group.leftmost_free_index(inline_proposals.iter().map(Some))?;

        let group = CoreGroup {
            public_group,
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            group_epoch_secrets,
            message_secrets_store,
            own_leaf_index,
            // TODO(#1357)
            resumption_psk_store: ResumptionPskStore::new(32),
        };

        let leaf_extensions = params.take_leaf_extensions();
        let leaf_capabilities = params.take_leaf_capabilities();
        let params = CreateCommitParams::builder()
            .framing_parameters(*params.framing_parameters())
            .proposal_store(params.proposal_store())
            .inline_proposals(inline_proposals)
            .commit_type(CommitType::External)
            .credential_with_key(params_credential_with_key)
            .leaf_capabilities(leaf_capabilities)
            .leaf_extensions(leaf_extensions)
            .build();

        // Immediately create the commit to add ourselves to the group.
        let create_commit_result = group.create_commit(params, provider, signer);
        debug_assert!(
            create_commit_result.is_ok(),
            "Error creating commit {create_commit_result:?}"
        );

        Ok((
            group,
            create_commit_result.map_err(|_| ExternalCommitError::CommitError)?,
        ))
    }
}
