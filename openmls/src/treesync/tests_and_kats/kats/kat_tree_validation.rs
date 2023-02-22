//! ## Tree Validation
//!
//! Parameters:
//! * Ciphersuite
//!
//! Format:
//! ```text
//! {
//!   "cipher_suite": /* uint16 */,
//!   // Chosen by the generator
//!   "tree": /* hex-encoded binary data */,
//!   "group_id": /* hex-encoded binary data */,
//!   // Computed values
//!   "resolutions": [
//!     [uint32, ...],
//!   ...
//!   ],
//!   "tree_hashes": [
//!     /* hex-encoded binary data */,
//!   ...
//!   ]
//! }
//! ```
//!
//! `tree` contains a TLS-serialized ratchet tree, as in
//! [the `ratchet_tree` extension](https://tools.ietf.org/html/draft-ietf-mls-protocol-17#section-12.4.3.3)
//!
//! Verification:
//! * Verify that the resolution of each node in tree with node index `i` matches
//!   `resolutions[i]`.
//! * Verify that the tree hash of each node in tree with node index `i` matches
//!   `tree_hashes[i]`.
//! * [Verify the parent hashes](https://tools.ietf.org/html/draft-ietf-mls-protocol-17#section-7.9.2)
//!   of `tree` as when joining the group.
//! * Verify the signatures on all leaves of `tree` using the provided `group_id`
//!   as context.
//!
//! ### Origins of Test Trees
//! Trees in the test vector are ordered according to increasing complexity. Let
//! `get_tree(n)` denote the tree generated as follows: Initialize a tree
//! with a single node. For `i=0` to `n - 1`, leaf with leaf index `i`
//! commits adding a member (with leaf index `i + 1`).
//!
//! Note that the following tests cover `get_tree(n)` for all `n` in
//! `[2, 3, ..., 9, 32, 33, 34]`.
//!
//! * Full trees: `get_tree(n)` for `n` in `[2, 4, 8, 32]`.
//! * A tree with internal blanks: start with `get_tree(8)`; then the leaf with
//!   index `0` commits removing leaves `2` and `3`, and adding new member.
//! * Trees with trailing blanks: `get_tree(n)` for `n` in `[3, 5, 7, 33]`.
//! * A tree with internal blanks and skipping blanks in the parent hash links:
//!   start with `get_tree(8)`; then the leaf with index `0` commits removing
//!   leaves `1`, `2` and `3`.
//! * Trees with skipping trailing blanks in the parent hash links:
//!   `get_tree(n)` for `n` in `[3, 34]`.
//! * A tree with unmerged leaves: start with `get_tree(7)`, then the leaf
//!   with index `0` adds a member.
//! * A tree with unmerged leaves and skipping blanks in the parent hash links:
//!   the tree from [Figure 20](https://tools.ietf.org/html/draft-ietf-mls-protocol-17#appendix-A).

use std::collections::HashSet;

use ::serde::Deserialize;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsCryptoProvider};
use tls_codec::Deserialize as TlsDeserialize;

use crate::{
    binary_tree::array_representation::TreeNodeIndex, test_utils::*, treesync::Node,
    treesync::TreeSync,
};

#[derive(Deserialize)]
struct TreeHash(#[serde(with = "hex")] Vec<u8>);

#[derive(Deserialize)]
struct TestElement {
    cipher_suite: u16,
    #[serde(with = "hex")]
    tree: Vec<u8>,
    #[serde(with = "hex")]
    #[allow(dead_code)] // TODO #1289: Remove
    group_id: Vec<u8>,
    resolutions: Vec<Vec<u32>>,
    tree_hashes: Vec<TreeHash>,
}

fn run_test_vector(test: TestElement, backend: &impl OpenMlsCryptoProvider) -> Result<(), String> {
    let ciphersuite = Ciphersuite::try_from(test.cipher_suite).unwrap();
    // Skip unsupported ciphersuites.
    if !backend
        .crypto()
        .supported_ciphersuites()
        .contains(&ciphersuite)
    {
        log::debug!("Unsupported ciphersuite {0:?} ...", test.cipher_suite);
        return Ok(());
    }

    let nodes = Vec::<Option<Node>>::tls_deserialize(&mut test.tree.as_slice()).unwrap();

    let treesync = TreeSync::from_nodes(backend, ciphersuite, &nodes)
        .map_err(|e| format!("Error while creating tree sync: {0:?}", e))?;

    let diff = treesync.empty_diff();

    for index in 0..nodes.len() {
        let tree_node_index = TreeNodeIndex::test_new(index as u32);
        let resolution = diff
            .resolution(tree_node_index, &HashSet::new())
            .into_iter()
            .map(|(index, _)| index.test_u32())
            .collect::<Vec<_>>();

        // Verify resolution
        assert_eq!(resolution, test.resolutions[index]);

        let tree_hash = diff
            .compute_tree_hash(backend, ciphersuite, tree_node_index, &HashSet::new())
            .unwrap();

        // Verify tree hash
        assert_eq!(tree_hash, test.tree_hashes[index].0);

        // TODO #1289: Verify the signature of the leaf nodes
    }

    Ok(())
}

#[apply(backends)]
fn read_test_vectors_tree_validation(backend: &impl OpenMlsCryptoProvider) {
    let _ = pretty_env_logger::try_init();
    log::debug!("Reading test vectors ...");

    let tests: Vec<TestElement> = read("test_vectors/tree-validation.json");

    for test_vector in tests {
        match run_test_vector(test_vector, backend) {
            Ok(_) => {}
            Err(e) => panic!("Error while checking PSK secret test vector.\n{e:?}"),
        }
    }
    log::trace!("Finished test vector verification");
}
