use crate::{
    ciphersuite::signable::Verifiable,
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
    ) -> Result<ExternalCommitResult, CoreGroupError> {
        let ciphersuite = Config::ciphersuite(group_info.ciphersuite())?;
        if !Config::supported_versions().contains(&group_info.version()) {
            return Err(ExternalCommitError::UnsupportedMlsVersion.into());
        }

        // Build the ratchet tree

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let extension_tree_option =
            try_nodes_from_extensions(group_info.other_extensions(), backend.crypto())?;
        let (nodes, enable_ratchet_tree_extension) = match extension_tree_option {
            Some(nodes) => (nodes, true),
            None => match tree_option {
                Some(n) => (n.into(), false),
                None => return Err(ExternalCommitError::MissingRatchetTree.into()),
            },
        };

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the PGS, since we need to find the Credential to verify the
        // signature against.
        let treesync = TreeSync::from_nodes_without_leaf(backend, ciphersuite, nodes)?;

        if treesync.tree_hash() != group_info.tree_hash() {
            return Err(ExternalCommitError::TreeHashMismatch.into());
        }

        let external_pub = group_info
            .other_extensions()
            .iter()
            .find(|&e| e.extension_type() == ExtensionType::ExternalPub)
            .ok_or(ExternalCommitError::MissingExternalPubExtension.into())?
            .as_external_pub_extension()
            .map_err(|_| CoreGroupError::LibraryError)?
            .external_pub();

        let (init_secret, kem_output) = InitSecret::for_external_commit(
            backend,
            ciphersuite,
            group_info.version(),
            external_pub,
        )?;

        let group_context: GroupContext = group_info.into()?;

        // The `EpochSecrets` we create here are essentially zero, with the
        // exception of the `InitSecret`, which is all we need here for the
        // external commit.
        let epoch_secrets = EpochSecrets::with_init_secret(backend, init_secret)?;
        let (group_epoch_secrets, message_secrets) = epoch_secrets.split_secrets(
            group_context.tls_serialize_detached()?,
            treesync.leaf_count()?,
        );
        let message_secrets_store = MessageSecretsStore::new_with_secret(0, message_secrets);

        let interim_transcript_hash = update_interim_transcript_hash(
            ciphersuite,
            backend,
            &MlsPlaintextCommitAuthData::from(group_info.confirmation_tag()),
            group_info.confirmed_transcript_hash(),
        )?;

        // Prepare interim transcript hash
        let group = CoreGroup {
            ciphersuite,
            group_context,
            tree: treesync,
            interim_transcript_hash,
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            mls_version: group_info.version(),
            group_epoch_secrets,
            message_secrets_store,
        };

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        let mut inline_proposals = vec![external_init_proposal];

        // If there is a group member in the group with the same identity as us,
        // commit a remove proposal.
        for (leaf_index, key_package) in group.treesync().full_leaves()? {
            if key_package.credential().identity()
                == params.credential_bundle().credential().identity()
            {
                let remove_proposal = Proposal::Remove(RemoveProposal {
                    removed: key_package.hash_ref(backend.crypto())?,
                });
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
