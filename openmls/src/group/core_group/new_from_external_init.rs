use crate::{
    group::errors::ExternalCommitError,
    messages::proposals::{ExternalInitProposal, Proposal},
    treesync::{errors::TreeSyncFromNodesError, node::Node},
};

use super::{
    create_commit_params::{CommitType, CreateCommitParams},
    CoreGroup,
};
use crate::group::core_group::*;

pub(crate) type ExternalCommitResult = (CoreGroup, CreateCommitResult);

impl CoreGroup {
    /// Join a group without the help of an internal member. This function
    /// requires a `PublicGroupState`, as well as the corresponding public tree
    /// `nodes`. After the group state is initialized, this function creates an
    /// `ExternalInit` proposal and commits it along with the given proposals by
    /// reference and by value.
    ///
    /// Returns the new `CoreGroup` object, as well as the `MlsPlaintext`
    /// containing the commit.
    pub(crate) fn join_by_external_commit(
        backend: &impl OpenMlsCryptoProvider,
        params: CreateCommitParams,
        tree_option: Option<&[Option<Node>]>,
        group_info: GroupInfo,
    ) -> Result<ExternalCommitResult, ExternalCommitError> {
        let ciphersuite = group_info.group_context().ciphersuite();
        if group_info.group_context().protocol_version() != ProtocolVersion::Mls10 {
            return Err(ExternalCommitError::UnsupportedMlsVersion);
        }

        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let extension_tree_option =
            try_nodes_from_extensions(group_info.extensions()).map_err(|e| match e {
                ExtensionError::DuplicateRatchetTreeExtension => {
                    ExternalCommitError::DuplicateRatchetTreeExtension
                }
                _ => LibraryError::custom("Unexpected extension error").into(),
            })?;
        let (nodes, enable_ratchet_tree_extension) = match extension_tree_option {
            Some(nodes) => (nodes, true),
            None => match tree_option {
                Some(n) => (n.into(), false),
                None => return Err(ExternalCommitError::MissingRatchetTree),
            },
        };

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the PGS, since we need to find the Credential to verify the
        // signature against.
        let treesync = TreeSync::from_nodes_without_leaf(backend, ciphersuite, nodes).map_err(
            |e| match e {
                TreeSyncFromNodesError::LibraryError(e) => e.into(),
                TreeSyncFromNodesError::PublicTreeError(e) => {
                    ExternalCommitError::PublicTreeError(e)
                }
            },
        )?;

        if treesync.tree_hash() != group_info.group_context().tree_hash() {
            return Err(ExternalCommitError::TreeHashMismatch);
        }

        // Obtain external_pub from GroupInfo extensions.
        // TODO(#720): Check for duplicates.
        let external_pub = {
            let ext = group_info
                .extensions()
                .iter()
                .find(|ext| matches!(ext, Extension::ExternalPub(_)))
                .ok_or(ExternalCommitError::MissingExternalPub)?
                .as_external_pub_extension()
                .map_err(LibraryError::custom(
                    "We found an `ExternalPub` so `as_external_pub_extension` must not fail.",
                ))?;

            ext.external_pub()
        };

        let (init_secret, kem_output) =
            InitSecret::from_public_group_state(backend, &group_info, external_pub.as_slice())
                .map_err(|_| ExternalCommitError::UnsupportedCiphersuite)?;

        // The `EpochSecrets` we create here are essentially zero, with the
        // exception of the `InitSecret`, which is all we need here for the
        // external commit.
        let epoch_secrets = EpochSecrets::with_init_secret(backend, init_secret)
            .map_err(LibraryError::unexpected_crypto_error)?;
        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            group_info
                .group_context()
                .tls_serialize_detached()
                .map_err(LibraryError::missing_bound_check)?,
            treesync
                .leaf_count()
                .map_err(|_| LibraryError::custom("The tree was too big"))?,
            // We use a fake own index of 0 here, as we're not going to use the
            // tree for encryption until after the first commit. This issue is
            // tracked in #767.
            0u32,
        );
        let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

        let interim_transcript_hash = {
            if group_info.group_context().epoch() == GroupEpoch::from(0) {
                vec![]
            } else {
                // New members compute the interim transcript hash using
                // the confirmation_tag field of the GroupInfo struct.
                compute_interim_transcript_hash(
                    ciphersuite,
                    backend,
                    group_info.group_context().confirmed_transcript_hash(),
                    &InterimTranscriptHashInput::from(group_info.confirmation_tag()),
                )
                .unwrap()
            }
        };

        // Prepare interim transcript hash
        let group = CoreGroup {
            ciphersuite,
            group_context: group_info.group_context().clone(),
            tree: treesync,
            interim_transcript_hash: interim_transcript_hash,
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            mls_version: group_info.group_context().protocol_version(),
            group_epoch_secrets,
            message_secrets_store,
        };

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        let mut inline_proposals = vec![external_init_proposal];

        // If there is a group member in the group with the same identity as us,
        // commit a remove proposal.
        for Member {
            index, identity, ..
        } in group.treesync().full_leave_members()?
        {
            if identity == params.credential_bundle().credential().identity() {
                let remove_proposal = Proposal::Remove(RemoveProposal { removed: index });
                inline_proposals.push(remove_proposal);
                break;
            };
        }

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
