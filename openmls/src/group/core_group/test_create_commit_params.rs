use core_group::{create_commit_params::CreateCommitParams, proposals::ProposalStore};
use openmls_traits::types::SignatureScheme;

use crate::{credentials::CredentialType, test_utils::*};

use super::*;

// Tests that the builder for CreateCommitParams works as expected
#[apply(backends)]
fn build_create_commit_params(backend: &impl OpenMlsCryptoProvider) {
    let framing_parameters: FramingParameters =
        FramingParameters::new(&[1, 2, 3], WireFormat::PrivateMessage);
    let (credential, signature_keys) = test_utils::new_credential(
        backend,
        b"Client",
        CredentialType::Basic,
        SignatureScheme::ED25519,
    );
    let proposal_store: &ProposalStore = &ProposalStore::new();
    let inline_proposals: Vec<Proposal> = vec![];
    let force_self_update: bool = true;

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(proposal_store)
        .inline_proposals(inline_proposals.clone())
        .force_self_update(force_self_update)
        .build();

    assert_eq!(params.framing_parameters(), &framing_parameters);
    assert_eq!(params.proposal_store(), proposal_store);
    assert_eq!(params.inline_proposals(), inline_proposals);
    assert_eq!(params.force_self_update(), force_self_update);
}
