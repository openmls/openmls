use crate::{
    binary_tree::array_representation::LeafNodeIndex,
    group::errors::ExternalCommitError,
    messages::proposals::{ExternalInitProposal, Proposal},
    treesync::node::Node,
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    CoreGroup,
};
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
    pub(crate) fn join_by_external_commit(
        backend: &impl OpenMlsCryptoProvider,
        params: CreateCommitParams,
        tree_option: Option<&[Option<Node>]>,
        verifiable_group_info: VerifiableGroupInfo,
    ) -> Result<ExternalCommitResult, ExternalCommitError> {
        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let extension_tree_option = try_nodes_from_extensions(verifiable_group_info.extensions());
        let (nodes, enable_ratchet_tree_extension) = match extension_tree_option {
            Some(nodes) => (nodes, true),
            None => match tree_option {
                Some(n) => (n.into(), false),
                None => return Err(ExternalCommitError::MissingRatchetTree),
            },
        };

        let (public_group, group_info_extensions) =
            PublicGroup::from_external(backend, &nodes, verifiable_group_info)?;
        let group_context = public_group.group_context();

        // Obtain external_pub from GroupInfo extensions.
        let external_pub = group_info_extensions
            .external_pub()
            .ok_or(ExternalCommitError::MissingExternalPub)?
            .external_pub();

        let (init_secret, kem_output) =
            InitSecret::from_group_context(backend, group_context, external_pub.as_slice())
                .map_err(|_| ExternalCommitError::UnsupportedCiphersuite)?;

        // The `EpochSecrets` we create here are essentially zero, with the
        // exception of the `InitSecret`, which is all we need here for the
        // external commit.
        let epoch_secrets = EpochSecrets::with_init_secret(backend, init_secret)
            .map_err(LibraryError::unexpected_crypto_error)?;
        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            group_context
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
            public_group.treesync().leaf_count(),
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
        for Member {
            index, identity, ..
        } in public_group.treesync().full_leave_members()
        {
            if identity == params.credential_bundle().credential().identity() {
                let remove_proposal = Proposal::Remove(RemoveProposal { removed: index });
                inline_proposals.push(remove_proposal);
                break;
            };
        }

        let own_leaf_index = public_group.free_leaf_index(inline_proposals.iter().map(Some))?;

        let group = CoreGroup {
            public_group,
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            group_epoch_secrets,
            message_secrets_store,
            own_leaf_index,
        };

        let params = CreateCommitParams::builder()
            .framing_parameters(*params.framing_parameters())
            .credential_bundle(params.credential_bundle())
            .proposal_store(params.proposal_store())
            .inline_proposals(inline_proposals)
            .commit_type(CommitType::External)
            .build();

        // Immediately create the commit to add ourselves to the group.
        let create_commit_result = group.create_commit(params, backend);
        debug_assert!(
            create_commit_result.is_ok(),
            "Error creating commit {:?}",
            create_commit_result
        );

        Ok((
            group,
            create_commit_result.map_err(|_| ExternalCommitError::CommitError)?,
        ))
    }
}
