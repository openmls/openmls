//! TreeKEM test vectors
//!
//! See https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! for more description on the test vectors.
//!
//! The test vector describes a tree of `n` leaves adds a new leaf with
//! `my_key_package`, `my_leaf_secret` and `my_path_secret` (common ancestor of
//! `add_sender` and `my_key_package`). Then an update, sent by `update_sender`
//! with `update_path` is processed, which is processed by the newly added leaf
//! as well.
//!
//! Some more points
//! * update path with empty exclusion list.

use openmls::ciphersuite::signable::Signable;
use openmls::kat_generation_api::*;
use openmls::prelude::*;
#[cfg(test)]
use openmls::test_util::read;
//{
//    ciphersuite::signable::Signable,
//    codec::Decode,
//    credentials::{CredentialBundle, CredentialType},
//    prelude::KeyPackageBundlePayload,
//    test_util::hex_to_bytes,
//};
//use openmls::{
//    ciphersuite::Secret,
//    config::Config,
//    config::ProtocolVersion,
//    error::*,
//    extensions::{Extension, RatchetTreeExtension},
//    key_packages::KeyPackage,
//    messages::PathSecret,
//    tree::{treemath::*, CiphersuiteName, HashSet, LeafIndex, NodeIndex, RatchetTree, UpdatePath},
//};

use openmls::messages::PathSecret;
use openmls::test_util::hex_to_bytes;
use openmls::tree::{NodeIndex, RatchetTree, UpdatePath};
use std::collections::HashSet;

use serde::{self, Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TreeKemTestVector {
    pub cipher_suite: u16,

    // Chosen by the generator
    pub ratchet_tree_before: String,

    pub add_sender: u32,
    pub my_leaf_secret: String,
    pub my_key_package: String,
    pub my_path_secret: String,

    pub update_sender: u32,
    pub update_path: String,
    pub update_group_context: String,

    // Computed values
    pub tree_hash_before: String,
    pub root_secret_after_add: String,
    pub root_secret_after_update: String,
    pub ratchet_tree_after: String,
    pub tree_hash_after: String,
}

pub fn run_test_vector(test_vector: TreeKemTestVector) -> Result<(), TreeKemTestVectorError> {
    log::debug!("Running TreeKEM test vector");
    let ciphersuite =
        CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    let ciphersuite = Config::ciphersuite(ciphersuite).expect("Invalid ciphersuite");

    let tree_extension_before =
        RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_before))
            .expect("Error decoding ratchet tree");
    let ratchet_tree_before = tree_extension_before.into_vector_test();

    let my_leaf_secret = Secret::from_slice_test(
        &hex_to_bytes(&test_vector.my_leaf_secret),
        ProtocolVersion::default(),
        ciphersuite,
    );

    let my_key_package = KeyPackage::decode_detached(&hex_to_bytes(&test_vector.my_key_package))
        .expect("failed to decode my_key_package from test vector.");

    // We clone the leaf secret here, because we need it later to re-create the
    // KeyPackageBundle.
    let credential_bundle = CredentialBundle::new(
        "username".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
    )
    .unwrap();
    let my_key_package_bundle = KeyPackageBundlePayload::from_key_package_and_leaf_secret(
        my_leaf_secret.clone(),
        &my_key_package,
    )
    .sign(&credential_bundle)
    .unwrap();

    // Check tree hashes.
    let mut tree_before =
        RatchetTree::new_from_nodes_test(my_key_package_bundle, &ratchet_tree_before).unwrap();
    //crate::utils::_print_tree(&tree_before, "Tree before");

    if hex_to_bytes(&test_vector.tree_hash_before) != tree_before.tree_hash_test() {
        if cfg!(test) {
            panic!("Tree hash mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeTreeHashMismatch);
    }

    let tree_extension_after =
        RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_after))
            .expect("Error decoding ratchet tree");
    let ratchet_tree_after = tree_extension_after.into_vector_test();

    let my_key_package_bundle =
        KeyPackageBundlePayload::from_key_package_and_leaf_secret(my_leaf_secret, &my_key_package)
            .sign(&credential_bundle)
            .unwrap();
    let tree_after =
        RatchetTree::new_from_nodes_test(my_key_package_bundle, &ratchet_tree_after).unwrap();
    //crate::utils::_print_tree(&tree_after, "Tree after");

    if hex_to_bytes(&test_vector.tree_hash_after) != tree_after.tree_hash_test() {
        if cfg!(test) {
            panic!("Tree hash mismatch in the 'after' tree.");
        }
        return Err(TreeKemTestVectorError::AfterTreeHashMismatch);
    }

    // Verify parent hashes
    if tree_before.verify_parent_hashes().is_err() {
        if cfg!(test) {
            panic!("Parent hash mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeParentHashMismatch);
    }
    if tree_after.verify_parent_hashes().is_err() {
        if cfg!(test) {
            panic!("Parent hash mismatch in the 'after' tree.");
        }
        return Err(TreeKemTestVectorError::AfterParentHashMismatch);
    }

    // Initialize private portion of the RatchetTree
    let add_sender = test_vector.add_sender;
    log::trace!(
        "Add sender index: {:?}",
        NodeIndex::from(LeafIndex::from(add_sender))
    );
    log::trace!(
        "Test client index: {:?}",
        NodeIndex::from(tree_before.own_node_index_test())
    );
    log::trace!(
        "Updater index: {:?}",
        NodeIndex::from(LeafIndex::from(test_vector.update_sender))
    );
    let common_ancestor = common_ancestor_index_test(
        NodeIndex::from(LeafIndex::from(add_sender)),
        NodeIndex::from(tree_before.own_node_index_test()),
    );
    log::trace!("Common ancestor: {:?}", common_ancestor);
    let path = parent_direct_path_test(common_ancestor, tree_before.leaf_count()).unwrap();
    log::trace!("path: {:?}", path);
    let start_secret = Secret::from_slice_test(
        &hex_to_bytes(&test_vector.my_path_secret),
        ProtocolVersion::default(),
        ciphersuite,
    )
    .into();
    tree_before.continue_path_secrets_test(ciphersuite, start_secret, &path);

    // Check if the root secrets match up.
    let root_secret_after_add: &PathSecret = &Secret::from_slice_test(
        &hex_to_bytes(&test_vector.root_secret_after_add),
        ProtocolVersion::default(),
        ciphersuite,
    )
    .into();

    if root_secret_after_add
        != tree_before
            .path_secret_test(root_test(tree_before.leaf_count()))
            .unwrap()
    {
        if cfg!(test) {
            panic!("Root secret mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeRootSecretMismatch);
    }

    // Apply the update path
    let update_path = UpdatePath::decode_detached(&hex_to_bytes(&test_vector.update_path)).unwrap();
    log::trace!("UpdatePath: {:?}", update_path);
    let group_context = hex_to_bytes(&test_vector.update_group_context);
    let _commit_secret = tree_before
        .update_path_test(
            LeafIndex::from(test_vector.update_sender),
            &update_path,
            &group_context,
            HashSet::new(),
        )
        .unwrap();

    // Rename to avoid confusion.
    let tree_after = tree_before;
    let root_secret_after = tree_after.path_secrets_test().last().unwrap();
    let root_secret_after_update: &PathSecret = &Secret::from_slice_test(
        &hex_to_bytes(&test_vector.root_secret_after_update),
        ProtocolVersion::default(),
        ciphersuite,
    )
    .into();

    if root_secret_after_update != root_secret_after {
        if cfg!(test) {
            panic!("Root secret mismatch in the 'after' tree.");
        }
        return Err(TreeKemTestVectorError::AfterRootSecretMismatch);
    }

    let tree_extension_after =
        RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_after))
            .expect("Error decoding ratchet tree");
    let ratchet_tree_after = tree_extension_after.into_vector_test();

    if tree_after.public_key_tree_copy() != ratchet_tree_after {
        if cfg!(test) {
            panic!("Ratchet tree mismatch in the after the update.");
        }
        return Err(TreeKemTestVectorError::AfterRatchetTreeMismatch);
    }

    log::debug!("Done verifying TreeKEM test vector");

    Ok(())
}

#[test]
fn read_test_vector() {
    let tests: Vec<TreeKemTestVector> = read("test_vectors/kat_tree_kem_openmls.json");

    for test_vector in tests {
        run_test_vector(test_vector).expect("error while checking tree kem test vector.");
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum TreeKemTestVectorError {
    BeforeTreeHashMismatch,
    AfterTreeHashMismatch,
    BeforeParentHashMismatch,
    AfterParentHashMismatch,
    BeforeRootSecretMismatch,
    AfterRootSecretMismatch,
    AfterRatchetTreeMismatch,
}
