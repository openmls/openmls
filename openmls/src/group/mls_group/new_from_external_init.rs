use crate::{
    ciphersuite::signable::Verifiable,
    credentials::CredentialBundle,
    messages::{
        proposals::{ExternalInitProposal, Proposal},
        PublicGroupState,
    },
    node::Node,
    prelude::{plaintext::MlsPlaintext, KeyPackageBundle},
};

use crate::group::mls_group::*;
use crate::group::ExternalInitError;

use super::{MlsGroup, PskFetcher};

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
    pub(crate) fn new_from_external_init_internal(
        nodes_option: Option<Vec<Option<Node>>>,
        psk_fetcher_option: Option<PskFetcher>,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        proposals_by_reference: &[MlsPlaintext],
        proposals_by_value: &[Proposal],
        verifiable_public_group_state: VerifiablePublicGroupState,
    ) -> ExternalInitResult {
        let ciphersuite = Config::ciphersuite(verifiable_public_group_state.payload().ciphersuite)?;

        // Create a RatchetTree from the given nodes. We have to do this before
        // verifying the PGS, since we need to find the Credential to verify the
        // signature against.
        let (tree, use_ratchet_tree_extension) = MlsGroup::tree_from_extension_or_nodes(
            ciphersuite,
            verifiable_public_group_state.payload().tree_hash.as_slice(),
            nodes_option,
            verifiable_public_group_state
                .payload()
                .extensions
                .as_slice(),
            None,
        )?;

        // Verify the public group state using the credential of the signer.
        let pgs_signer_leaf: &Node = tree
            .nodes
            .get(NodeIndex::from(verifiable_public_group_state.payload().signer_index).as_usize())
            .ok_or(ExternalInitError::UnknownSigner)?;
        let pgs_signer_credential = pgs_signer_leaf
            .key_package()
            .ok_or(ExternalInitError::UnknownSigner)?
            .credential();
        let pgs: PublicGroupState = verifiable_public_group_state
            .verify(pgs_signer_credential)
            .map_err(|_| ExternalInitError::InvalidPublicGroupState)?;

        let (init_secret, kem_output) = InitSecret::from_public_group_state(&pgs)?;

        let external_init_proposal = Proposal::ExternalInit(ExternalInitProposal::from(kem_output));

        let key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], credential_bundle, vec![])?;

        let add_proposal = Proposal::Add(AddProposal {
            key_package: key_package_bundle.key_package().clone(),
        });

        let mut pbv_references: Vec<&Proposal> = proposals_by_value.iter().map(|p| p).collect();
        let pbr_references: Vec<&MlsPlaintext> = proposals_by_reference.iter().map(|p| p).collect();

        pbv_references.push(&add_proposal);
        pbv_references.push(&external_init_proposal);

        // Leaving he confirmed_transcript_hash empty for now. It will later be
        // set using the interim transcrip hash from the PGS.
        let group_context = GroupContext::new(
            pgs.group_id,
            pgs.epoch,
            pgs.tree_hash.as_slice().to_vec(),
            vec![],
            pgs.extensions.as_slice(),
        );

        let epoch_secrets = EpochSecrets::with_init_secret(init_secret);
        let secret_tree = SecretTree::new(epoch_secrets.encryption_secret(), tree.leaf_count());

        let group = MlsGroup {
            ciphersuite,
            group_context,
            epoch_secrets,
            secret_tree: RefCell::new(secret_tree),
            tree: RefCell::new(tree),
            interim_transcript_hash: pgs.interim_transcript_hash.into_vec(),
            use_ratchet_tree_extension,
            mls_version: ciphersuite.version(),
        };

        // Immediately create the commit to add ourselves to the group.
        let (mls_plaintext, option_welcome, option_kpb) = group.create_commit(
            aad,
            credential_bundle,
            &pbr_references,
            &pbv_references,
            true, // force self-update
            psk_fetcher_option,
        )?;

        Ok((group, mls_plaintext, option_welcome, option_kpb))
    }
}
