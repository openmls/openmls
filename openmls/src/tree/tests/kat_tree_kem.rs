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

#[cfg(test)]
use crate::test_util::read;
use crate::{
    ciphersuite::signable::Signable,
    credentials::{CredentialBundle, CredentialType},
    node::Node,
    prelude::KeyPackageBundlePayload,
    test_util::hex_to_bytes,
};
use crate::{
    ciphersuite::Secret,
    config::Config,
    config::ProtocolVersion,
    key_packages::KeyPackage,
    messages::PathSecret,
    tree::{treemath::*, CiphersuiteName, HashSet, LeafIndex, NodeIndex, RatchetTree, UpdatePath},
};

use serde::{self, Deserialize, Serialize};
use std::convert::TryFrom;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerializeTrait, TlsVecU32};

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
    log::trace!("{:?}", test_vector);
    let ciphersuite =
        CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    let ciphersuite = Config::ciphersuite(ciphersuite).expect("Invalid ciphersuite");

    log::trace!("ratchet tree before: {}", test_vector.ratchet_tree_before);
    let ratchet_tree_before_bytes = hex_to_bytes(&test_vector.ratchet_tree_before);
    let ratchet_tree_before =
        TlsVecU32::<Option<Node>>::tls_deserialize(&mut ratchet_tree_before_bytes.as_slice())
            .expect("Error decoding ratchet tree");

    let my_leaf_secret = Secret::from_slice(
        &hex_to_bytes(&test_vector.my_leaf_secret),
        ProtocolVersion::default(),
        ciphersuite,
    );

    let my_key_package =
        KeyPackage::tls_deserialize(&mut hex_to_bytes(&test_vector.my_key_package).as_slice())
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
        RatchetTree::new_from_nodes(my_key_package_bundle, ratchet_tree_before.as_slice()).unwrap();
    crate::utils::_print_tree(&tree_before, "Tree before");

    if hex_to_bytes(&test_vector.tree_hash_before) != tree_before.tree_hash() {
        if cfg!(test) {
            panic!("Tree hash mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeTreeHashMismatch);
    }

    let ratchet_tree_after_bytes = hex_to_bytes(&test_vector.ratchet_tree_after);
    let ratchet_tree_after =
        TlsVecU32::<Option<Node>>::tls_deserialize(&mut ratchet_tree_after_bytes.as_slice())
            .expect("Error decoding ratchet tree");

    let my_key_package_bundle =
        KeyPackageBundlePayload::from_key_package_and_leaf_secret(my_leaf_secret, &my_key_package)
            .sign(&credential_bundle)
            .unwrap();
    let tree_after =
        RatchetTree::new_from_nodes(my_key_package_bundle, ratchet_tree_after.as_slice()).unwrap();
    crate::utils::_print_tree(&tree_after, "Tree after");

    if hex_to_bytes(&test_vector.tree_hash_after) != tree_after.tree_hash() {
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
        NodeIndex::from(tree_before.own_node_index())
    );
    log::trace!(
        "Updater index: {:?}",
        NodeIndex::from(LeafIndex::from(test_vector.update_sender))
    );
    let common_ancestor = common_ancestor_index(
        NodeIndex::from(LeafIndex::from(add_sender)),
        NodeIndex::from(tree_before.own_node_index()),
    );
    log::trace!("Common ancestor: {:?}", common_ancestor);
    let path = parent_direct_path(common_ancestor, tree_before.leaf_count()).unwrap();
    log::trace!("path: {:?}", path);
    let mut start_secret =
        PathSecret::tls_deserialize(&mut hex_to_bytes(&test_vector.my_path_secret).as_slice())
            .expect("Error deserializing path secret.");
    start_secret.config(ciphersuite, ProtocolVersion::default());
    tree_before
        .private_tree_mut()
        .continue_path_secrets(ciphersuite, start_secret, &path);

    // Check if the root secrets match up.
    let mut root_secret_after_add = PathSecret::tls_deserialize(
        &mut hex_to_bytes(&test_vector.root_secret_after_add).as_slice(),
    )
    .expect("Error deserializing path secret.");
    root_secret_after_add.config(ciphersuite, ProtocolVersion::default());

    if &root_secret_after_add
        != tree_before
            .path_secret(root(tree_before.leaf_count()))
            .unwrap()
    {
        if cfg!(test) {
            panic!("Root secret mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeRootSecretMismatch);
    }

    // Apply the update path
    let update_path =
        UpdatePath::tls_deserialize(&mut hex_to_bytes(&test_vector.update_path).as_slice())
            .unwrap();
    log::trace!("UpdatePath: {:?}", update_path);
    let group_context = hex_to_bytes(&test_vector.update_group_context);
    let _commit_secret = tree_before
        .update_path(
            LeafIndex::from(test_vector.update_sender),
            &update_path,
            &group_context,
            HashSet::new(),
        )
        .unwrap();

    // Rename to avoid confusion.
    let tree_after = tree_before;
    let root_secret_after = tree_after.private_tree().path_secrets().last().unwrap();
    let mut root_secret_after_update = PathSecret::tls_deserialize(
        &mut hex_to_bytes(&test_vector.root_secret_after_update).as_slice(),
    )
    .expect("Error deserializing path secret.");
    root_secret_after_update.config(ciphersuite, ProtocolVersion::default());

    if &root_secret_after_update != root_secret_after {
        if cfg!(test) {
            log::error!(
                "expected root secret: {}",
                test_vector.root_secret_after_update
            );
            log::error!(
                "got root secret:      {}",
                crate::test_util::bytes_to_hex(
                    &root_secret_after.tls_serialize_detached().unwrap()
                )
            );
            panic!("Root secret mismatch in the 'after' tree.");
        }
        return Err(TreeKemTestVectorError::AfterRootSecretMismatch);
    }

    let ratchet_tree_after_bytes = hex_to_bytes(&test_vector.ratchet_tree_after);
    let ratchet_tree_after =
        TlsVecU32::<Option<Node>>::tls_deserialize(&mut ratchet_tree_after_bytes.as_slice())
            .expect("Error decoding ratchet tree");

    if tree_after.public_key_tree_copy() != ratchet_tree_after.as_slice() {
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
    let _ = pretty_env_logger::try_init();
    let tests: Vec<TreeKemTestVector> = read("test_vectors/kat_tree_kem_openmls.json");

    for test_vector in tests {
        run_test_vector(test_vector).expect("error while checking tree kem test vector.");
    }
}

implement_error! {
    pub enum TreeKemTestVectorError {
        BeforeTreeHashMismatch = "Tree hash mismatch in the 'before' tree.",
        AfterTreeHashMismatch = "Tree hash mismatch in the 'after' tree.",
        BeforeParentHashMismatch = "Parent hash mismatch in the 'before' tree.",
        AfterParentHashMismatch = "Parent hash mismatch in the 'after' tree.",
        BeforeRootSecretMismatch = "Root secret mismatch in the 'before' tree.",
        AfterRootSecretMismatch = "Root secret mismatch in the 'after' tree.",
        AfterRatchetTreeMismatch = "Ratchet tree mismatch in the after the update.",
    }
}
