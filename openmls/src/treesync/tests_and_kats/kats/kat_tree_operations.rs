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
    cipher_suite: u16,
    #[serde(with = "hex")]
    tree_before: Vec<u8>,
    #[serde(with = "hex")]
    proposal: Vec<u8>,
    proposal_sender: u32,
    #[serde(with = "hex")]
    tree_after: Vec<u8>,
    #[serde(with = "hex")]
    tree_hash_after: Vec<u8>,
    #[serde(with = "hex")]
    tree_hash_before: Vec<u8>,
}

fn run_test_vector(test: TestElement, provider: &impl OpenMlsProvider) -> Result<(), String> {
    let ciphersuite = Ciphersuite::try_from(test.cipher_suite).unwrap();

    let group_id = GroupId::random(provider.rand());

    let nodes = Vec::<Option<NodeIn>>::tls_deserialize_exact(test.tree_before).unwrap();

    let ratchet_tree = RatchetTree::from(RatchetTreeIn::from_nodes(nodes));

    let tree_before = TreeSync::from_ratchet_tree(provider.crypto(), ciphersuite, ratchet_tree)
        .map_err(|e| format!("Error while creating tree sync: {e:?}"))?;

    let tree_hash_before = tree_before.tree_hash();
    assert_eq!(test.tree_hash_before, tree_hash_before);

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
            provider.crypto(),
            &Secret::random(ciphersuite, provider.rand(), ProtocolVersion::Mls10).unwrap(),
            &[],
        )
        .unwrap(),
    );

    let mut group = PublicGroup::new(
        provider.crypto(),
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
        provider.crypto(),
        proposal,
        &Sender::Member(LeafNodeIndex::new(test.proposal_sender)),
    )
    .unwrap();

    proposal_queue.add(queued_proposal);

    let mut diff = group.empty_diff();

    diff.apply_proposals(&proposal_queue, None).unwrap();
    diff.update_group_context(provider.crypto()).unwrap();

    let staged_diff = diff
        .into_staged_diff(provider.crypto(), ciphersuite)
        .unwrap();

    group.merge_diff(staged_diff);

    let tree_after = group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .unwrap();

    assert_eq!(test.tree_after, tree_after);

    let tree_hash_after = group.group_context().tree_hash();
    assert_eq!(test.tree_hash_after, tree_hash_after);

    Ok(())
}

#[apply(providers)]
fn read_test_vectors_tree_operations(provider: &impl OpenMlsProvider) {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<TestElement> = read("test_vectors/tree-operations.json");

    for test_vector in tests {
        match run_test_vector(test_vector, provider) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking tree operations test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
