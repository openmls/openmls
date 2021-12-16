use mls_group::create_commit_params::CommitType;

use crate::{
    ciphersuite::signable::Verifiable,
    credentials::CredentialBundle,
    group::errors::ExternalInitError,
    messages::{
        proposals::{ExternalInitProposal, Proposal},
        public_group_state::{PublicGroupState, VerifiablePublicGroupState},
    },
    prelude::{plaintext::MlsPlaintext, KeyPackageBundle},
};

use super::{
    create_commit_params::CreateCommitParams,
    proposals::{ProposalStore, StagedProposal},
    MlsGroup,
};
use crate::group::mls_group::*;

pub type ExternalInitResult = Result<
    (
        MlsGroup,
        MlsPlaintext,
        Option<Welcome>,
        Option<KeyPackageBundle>,
    ),
    ExternalInitError,
>;

impl MlsGroup {
    /// Join a group based on a public group state and the given key package
    /// bundle.
    pub(crate) fn new_from_external_init_internal(
        backend: &impl OpenMlsCryptoProvider,
        framing_parameters: FramingParameters,
        nodes_option: Option<&[Option<Node>]>,
        credential_bundle: &CredentialBundle,
        proposals_by_reference: &[MlsPlaintext],
        proposals_by_value: &[Proposal],
        verifiable_public_group_state: VerifiablePublicGroupState,
    ) -> ExternalInitResult {
        let ciphersuite = Config::ciphersuite(verifiable_public_group_state.ciphersuite())?;
        if !Config::supported_versions().contains(&verifiable_public_group_state.version()) {
            return Err(ExternalInitError::UnsupportedMlsVersion);
        }

        let mut ratchet_tree_extensions = verifiable_public_group_state
            .other_extensions()
            .iter()
            .filter(|e| e.extension_type() == ExtensionType::RatchetTree)
            .collect::<Vec<&Extension>>();

        let ratchet_tree_extension = if ratchet_tree_extensions.is_empty() {
            None
        } else if ratchet_tree_extensions.len() == 1 {
            let extension = ratchet_tree_extensions
                .pop()
                // We know we only have one element
                .ok_or(ExternalInitError::LibraryError)?
                .as_ratchet_tree_extension()?;
            Some(extension)
        } else {
            // Throw an error if there is more than one ratchet tree extension.
            // This shouldn't be the case anyway, because extensions are checked
            // for uniqueness anyway when decoding them.
            // We have to see if this makes problems later as it's not something
            // required by the spec right now.
            return Err(ExternalInitError::DuplicateRatchetTreeExtension);
        };

        // Set nodes either from the extension or from the `nodes_option`.
        // If we got a ratchet tree extension in the welcome, we enable it for
        // this group. Note that this is not strictly necessary. But there's
        // currently no other mechanism to enable the extension.
        let (node_options, enable_ratchet_tree_extension) = match ratchet_tree_extension {
            Some(tree) => (tree.as_slice(), true),
            None => {
                if let Some(nodes) = nodes_option {
                    (nodes, false)
                } else {
                    return Err(ExternalInitError::MissingRatchetTree);
                }
            }
        };

        // Generate a fresh KeyPackageBundle for the new group.
        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], credential_bundle, backend, vec![])?;

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the PGS, since we need to find the Credential to verify the
        // signature against.
        let treesync = TreeSync::from_nodes_without_leaf(
            backend,
            ciphersuite,
            node_options,
            &key_package_bundle,
        )?;

        if treesync.tree_hash() != verifiable_public_group_state.tree_hash() {
            return Err(ExternalInitError::TreeHashMismatch);
        }

        let pgs_signer_leaf = treesync.leaf(verifiable_public_group_state.signer_index())?;
        let pgs_signer_credential = pgs_signer_leaf
            .ok_or(ExternalInitError::UnknownSender)?
            .key_package()
            .credential();
        let pgs: PublicGroupState = verifiable_public_group_state
            .verify(backend, pgs_signer_credential)
            .map_err(|_| ExternalInitError::InvalidPublicGroupState)?;

        let (init_secret, kem_output) = InitSecret::from_public_group_state(backend, &pgs)?;

        // Leaving he confirmed_transcript_hash empty for now. It will later be
        // set using the interim transcrip hash from the PGS.
        let group_context = GroupContext::new(
            pgs.group_id,
            pgs.epoch,
            pgs.tree_hash.as_slice().to_vec(),
            pgs.confirmed_transcript_hash.into(),
            pgs.group_context_extensions.as_slice(),
        )?;

        let epoch_secrets = EpochSecrets::with_init_secret(backend, init_secret)?;
        let secret_tree = SecretTree::new(
            epoch_secrets.encryption_secret(),
            treesync.leaf_count()?.into(),
        );

        // Prepare interim transcript hash
        let group = MlsGroup {
            ciphersuite,
            group_context,
            epoch_secrets,
            secret_tree: RefCell::new(secret_tree),
            tree: treesync,
            interim_transcript_hash: pgs.interim_transcript_hash.into(),
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            mls_version: pgs.version,
        };

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        let mut proposal_store = ProposalStore::default();
        for proposal in proposals_by_reference {
            let staged_proposal =
                StagedProposal::from_mls_plaintext(ciphersuite, backend, proposal.clone())?;
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
            // Populate the path
            .force_self_update(true)
            .build();

        // Immediately create the commit to add ourselves to the group.
        let (mls_plaintext, option_welcome, option_kpb) = group
            .create_commit(params, backend)
            .map_err(|_| ExternalInitError::CommitError)?;

        Ok((group, mls_plaintext, option_welcome, option_kpb))
    }
}
