use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::{Ciphersuite, CiphersuiteName},
    messages::proposals::{Proposal, ProposalOrRef, ProposalReference, RemoveProposal},
    test_utils::*,
};

/// This test encodes and decodes the `ProposalOrRef` struct and makes sure the
/// decoded values are the same as the original
#[apply(ciphersuites_and_backends)]
fn proposals_codec(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Proposal

    let remove_proposal = RemoveProposal { removed: 123 };
    let proposal = Proposal::Remove(remove_proposal);
    let proposal_or_ref = ProposalOrRef::Proposal(proposal.clone());
    let encoded = proposal_or_ref
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = ProposalOrRef::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");

    assert_eq!(proposal_or_ref, decoded);

    // Reference

    let reference = ProposalReference::from_proposal(ciphersuite, backend, &proposal)
        .expect("An unexpected error occurred.");
    let proposal_or_ref = ProposalOrRef::Reference(reference);
    let encoded = proposal_or_ref
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    let decoded = ProposalOrRef::tls_deserialize(&mut encoded.as_slice())
        .expect("An unexpected error occurred.");

    assert_eq!(proposal_or_ref, decoded);
}
