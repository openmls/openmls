use crate::{
    ciphersuite::signable::Verifiable,
    credentials::CredentialBundle,
    messages::{
        proposals::{ExternalInitProposal, Proposal},
        PublicGroupState,
    },
    node::Node,
    prelude::{plaintext::MlsPlaintext, KeyPackageBundle},
    tree::RatchetTree,
};

use crate::group::mls_group::*;
use crate::group::ExternalInitError;

use super::{MlsGroup, PskFetcher};

impl MlsGroup {
    pub(crate) fn new_from_external_init_internal(
        nodes_option: Option<Vec<Option<Node>>>,
        key_package_bundle: KeyPackageBundle,
        psk_fetcher_option: Option<PskFetcher>,
        aad: &[u8],
        credential_bundle: &CredentialBundle,
        proposals_by_reference: Vec<MlsPlaintext>,
        proposals_by_value: Vec<Proposal>,
        public_group_state: &PublicGroupState,
    ) -> Result<(Self, MlsPlaintext), ExternalInitError> {
        // Create a RatchetTree from the given nodes.
        let (tree, use_ratchet_tree_extension) = MlsGroup::tree_from_extension_or_nodes(
            public_group_state.tree_hash.as_slice(),
            nodes_option,
            public_group_state.extensions.as_slice(),
            key_package_bundle,
        )?;

        // Verify the public group state using the credential of the signer.
        let pgs_signer_leaf: &Node = tree
            .nodes
            .get(public_group_state.signer_index.into())
            .ok_or(ExternalInitError::UnknownSigner)?;
        let pgs_signer_credential = pgs_signer_leaf
            .key_package()
            .ok_or(ExternalInitError::UnknownSigner)?
            .credential();
        public_group_state
            .verify(pgs_signer_credential)
            .map_err(|_| ExternalInitError::InvalidPublicGroupState)?;

        let ciphersuite = Config::ciphersuite(public_group_state.ciphersuite)?;

        let (init_secret, kem_output) =
            InitSecret::from_external_pub(ciphersuite, &public_group_state.external_pub)?;

        let external_init_proposal = ExternalInitProposal::from(kem_output);

        proposals_by_value.push(Proposal::ExternalInit(external_init_proposal));
        let pbv_references: Vec<&Proposal> = proposals_by_value.iter().map(|p| p).collect();
        let pbr_references: Vec<&MlsPlaintext> = proposals_by_reference.iter().map(|p| p).collect();

        // Filter proposals
        let (proposal_queue, contains_own_updates) = ProposalQueue::filter_proposals(
            ciphersuite,
            &pbr_references,
            &pbv_references,
            self.tree().own_node_index(),
            self.tree().leaf_count(),
        )?;

        // Leaving he confirmed_transcript_hash empty for now. It will later be
        // set using the interim transcrip hash from the PGS.
        let group_context = GroupContext::new(
            public_group_state.group_id,
            public_group_state.epoch,
            public_group_state.tree_hash.as_slice().to_vec(),
            vec![],
            public_group_state.extensions.as_slice(),
        );

        let group = MlsGroup {
            ciphersuite,
            group_context,
            epoch_secrets,
            secret_tree: todo!(),
            tree: todo!(),
            interim_transcript_hash: todo!(),
            use_ratchet_tree_extension,
            mls_version: todo!(),
        };
        todo!()
    }
}
