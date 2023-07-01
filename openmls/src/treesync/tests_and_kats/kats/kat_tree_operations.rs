//! ## Tree Operations
//!
//! Format:
//! ```text
//! {
//!     // Chosen by the generator
//!     "tree_before": /* hex-encoded TLS-serialized ratchet tree */,
//!     "proposal": /* hex-encoded TLS-serialized Proposal */,
//!     "proposal_sender": /* uint32 */,
//!   
//!     // Computed values
//!     "tree_after": /* hex-encoded TLS-serialized ratchet tree */,
//! }
//! ```
//!
//! The type of `proposal` is either `add`, `remove` or `update`.
//!
//! Verification:
//! * Compute `candidate_tree_after` by applying `proposal` sent by the member
//!   with index `proposal_sender` to `tree_before`.
//! * Verify that serialized `candidate_tree_after` matches the provided `tree_after`
//!   value.

use ::serde::Deserialize;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::{Mac, Secret},
    extensions::Extensions,
    framing::Sender,
    group::{GroupContext, GroupEpoch, GroupId, ProposalQueue, PublicGroup, QueuedProposal},
    messages::{proposals::Proposal, proposals_in::ProposalIn, ConfirmationTag},
    test_utils::*,
    treesync::{node::NodeIn, RatchetTree, RatchetTreeIn, TreeSync},
    versions::ProtocolVersion,
};

#[derive(Deserialize)]
struct TestElement {
    #[serde(with = "hex")]
    tree_before: Vec<u8>,
    #[serde(with = "hex")]
    proposal: Vec<u8>,
    proposal_sender: u32,
    #[serde(with = "hex")]
    tree_after: Vec<u8>,
}

fn run_test_vector(test: TestElement, backend: &impl OpenMlsProvider) -> Result<(), String> {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

    let group_id = GroupId::random(backend.rand());

    let nodes = Vec::<Option<NodeIn>>::tls_deserialize_exact(test.tree_before).unwrap();

    let ratchet_tree = RatchetTree::from(RatchetTreeIn::from_nodes(nodes));

    let tree_before = TreeSync::from_ratchet_tree(backend.crypto(), ciphersuite, ratchet_tree)
        .map_err(|e| format!("Error while creating tree sync: {e:?}"))?;

    let group_context = GroupContext::new(
        ciphersuite,
        group_id,
        GroupEpoch::from(0),
        vec![],
        vec![],
        Extensions::empty(),
    );
    let initial_confirmation_tag = ConfirmationTag(
        Mac::new(
            backend.crypto(),
            &Secret::random(ciphersuite, backend.rand(), ProtocolVersion::Mls10).unwrap(),
            &[],
        )
        .unwrap(),
    );

    let mut group = PublicGroup::new(
        backend.crypto(),
        tree_before,
        group_context,
        initial_confirmation_tag,
    )
    .unwrap();

    let mut proposal_queue = ProposalQueue::default();

    let proposal_in = ProposalIn::tls_deserialize_exact(test.proposal).unwrap();

    let proposal = Proposal::from(proposal_in);

    let queued_proposal = QueuedProposal::from_proposal_and_sender(
        ciphersuite,
        backend.crypto(),
        proposal,
        &Sender::Member(LeafNodeIndex::new(test.proposal_sender)),
    )
    .unwrap();

    proposal_queue.add(queued_proposal);

    let mut diff = group.empty_diff();

    diff.apply_proposals(&proposal_queue, None).unwrap();

    let staged_diff = diff.into_staged_diff(backend.crypto(), ciphersuite).unwrap();

    group.merge_diff(staged_diff);

    let tree_after = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();

    assert_eq!(test.tree_after, tree_after);

    Ok(())
}

#[apply(backends)]
fn read_test_vectors_tree_operations(backend: &impl OpenMlsProvider) {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<TestElement> = read("test_vectors/tree-operations.json");

    for test_vector in tests {
        match run_test_vector(test_vector, backend) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking tree operations test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
