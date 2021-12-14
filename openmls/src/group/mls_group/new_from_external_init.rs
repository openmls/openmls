use crate::{
    ciphersuite::signable::Verifiable,
    credentials::CredentialBundle,
    messages::{
        proposals::{ExternalInitProposal, Proposal},
        public_group_state::{PublicGroupState, VerifiablePublicGroupState},
    },
    prelude::{plaintext::MlsPlaintext, KeyPackageBundle},
};

use crate::group::mls_group::*;
use crate::group::WelcomeError;

use super::{
    create_commit_params::CreateCommitParams,
    proposals::{ProposalStore, StagedProposal},
    MlsGroup,
};

pub type ExternalInitResult = Result<
    (
        MlsGroup,
        MlsPlaintext,
        Option<Welcome>,
        Option<KeyPackageBundle>,
    ),
    WelcomeError,
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
        key_package_bundle: KeyPackageBundle,
    ) -> ExternalInitResult {
        let ciphersuite = Config::ciphersuite(verifiable_public_group_state.ciphersuite())?;
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
                .ok_or(WelcomeError::LibraryError)?
                .as_ratchet_tree_extension()?;
            Some(extension)
        } else {
            // Throw an error if there is more than one ratchet tree extension.
            // This shouldn't be the case anyway, because extensions are checked
            // for uniqueness anyway when decoding them.
            // We have to see if this makes problems later as it's not something
            // required by the spec right now.
            return Err(WelcomeError::DuplicateRatchetTreeExtension);
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
                    return Err(WelcomeError::MissingRatchetTree);
                }
            }
        };

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the PGS, since we need to find the Credential to verify the
        // signature against.
        let treesync = TreeSync::from_nodes_without_leaf(
            backend,
            ciphersuite,
            &node_options,
            &key_package_bundle,
        )?;

        let pgs_signer_leaf = treesync.leaf(verifiable_public_group_state.signer_index())?;
        let pgs_signer_credential = pgs_signer_leaf
            .ok_or(WelcomeError::UnknownSender)?
            .key_package()
            .credential();
        let pgs: PublicGroupState = verifiable_public_group_state
            .verify(backend, pgs_signer_credential)
            .map_err(|_| WelcomeError::InvalidPublicGroupState)?;

        let (init_secret, kem_output) = InitSecret::from_public_group_state(&pgs)?;

        // Leaving he confirmed_transcript_hash empty for now. It will later be
        // set using the interim transcrip hash from the PGS.
        let group_context = GroupContext::new(
            pgs.group_id,
            pgs.epoch,
            pgs.tree_hash.as_slice().to_vec(),
            vec![],
            pgs.group_context_extensions.as_slice(),
        )?;

        let epoch_secrets = EpochSecrets::with_init_secret(backend, init_secret)?;
        let secret_tree = SecretTree::new(
            epoch_secrets.encryption_secret(),
            treesync.leaf_count()?.into(),
        );

        let group = MlsGroup {
            ciphersuite,
            group_context,
            epoch_secrets,
            secret_tree: RefCell::new(secret_tree),
            tree: treesync,
            interim_transcript_hash: pgs.interim_transcript_hash.into_vec(),
            use_ratchet_tree_extension: enable_ratchet_tree_extension,
            mls_version: version_from_suite(&ciphersuite.name()),
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
            // Populate the path
            .force_self_update(true)
            .build();

        // Immediately create the commit to add ourselves to the group.
        let (mls_plaintext, option_welcome, option_kpb) = group
            .create_commit(params, backend)
            .map_err(|_| WelcomeError::CommitError)?;

        Ok((group, mls_plaintext, option_welcome, option_kpb))
    }
}
