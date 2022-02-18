//! TreeKEM test vectors
//!
//! See <https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md>
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

use crate::{
    ciphersuite::{signable::Signable, CiphersuiteName, Secret},
    config::{Config, ProtocolVersion},
    credentials::{CredentialBundle, CredentialType},
    key_packages::KeyPackage,
    key_packages::KeyPackageBundlePayload,
    messages::PathSecret,
    schedule::CommitSecret,
    test_utils::*,
    treesync::{node::Node, treekem::UpdatePath, TreeSync},
};

#[cfg(any(feature = "test-utils", test))]
use crate::treesync::treekem::DecryptPathParams;

use openmls_traits::OpenMlsCryptoProvider;
use serde::{self, Deserialize, Serialize};
use std::{collections::HashSet, convert::TryFrom};
use tls_codec::{Deserialize as TlsDeserialize, TlsVecU32};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TreeKemTestVector {
    pub cipher_suite: u16,

    // Chosen by the generator
    pub ratchet_tree_before: String,

    pub add_sender: String,
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

#[cfg(any(feature = "test-utils", test))]
pub fn run_test_vector(
    test_vector: TreeKemTestVector,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<(), TreeKemTestVectorError> {
    use crate::prelude_test::hash_ref::KeyPackageRef;

    log::debug!("Running TreeKEM test vector");
    log::trace!("{:?}", test_vector);
    let ciphersuite =
        CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");

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
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let my_key_package_bundle = KeyPackageBundlePayload::from_key_package_and_leaf_secret(
        my_leaf_secret,
        &my_key_package,
        backend,
    )
    .expect("Coul not create KeyPackage.")
    .sign(backend, &credential_bundle)
    .expect("An unexpected error occurred.");

    let start_secret: PathSecret = Secret::from_slice(
        hex_to_bytes(&test_vector.my_path_secret).as_slice(),
        ProtocolVersion::default(),
        ciphersuite,
    )
    .into();

    // Create the tree (including private values). This checks parent hashes as
    // well.
    let (mut tree_before, commit_secret_option_before) = if let Ok((tree, commit_secret_option)) =
        TreeSync::from_nodes_with_secrets(
            backend,
            ciphersuite,
            ratchet_tree_before.as_slice(),
            &KeyPackageRef::from_slice(hex_to_bytes(&test_vector.add_sender).as_slice()),
            start_secret,
            my_key_package_bundle,
        ) {
        (tree, commit_secret_option)
    } else {
        if cfg!(test) {
            panic!("Parent hash mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeParentHashMismatch);
    };

    // Verify that the tree hash of tree_before equals tree_hash_before.
    if hex_to_bytes(&test_vector.tree_hash_before) != tree_before.tree_hash() {
        if cfg!(test) {
            panic!("Tree hash mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeTreeHashMismatch);
    }

    // We can't get hold of the root secret, but we can get hold of the commit
    // secret. So we're deriving the commit secret from the root secret given in
    // the kat here.
    let secret = Secret::from_slice(
        hex_to_bytes(&test_vector.root_secret_after_add).as_slice(),
        ProtocolVersion::default(),
        ciphersuite,
    );
    let path_secret: PathSecret = secret.into();
    let commit_secret_after_add_kat: CommitSecret = path_secret
        .derive_path_secret(backend, ciphersuite)
        .expect("error deriving commit secret")
        .into();

    // Verify that the root secret for the initial tree matches
    // root_secret_after_add. (Checked here by comparing the commit secrets.)
    if commit_secret_after_add_kat.as_slice()
        != commit_secret_option_before
            .expect("didn't get a commit secret from tree before")
            .as_slice()
    {
        if cfg!(test) {
            panic!("Root secret mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeRootSecretMismatch);
    }

    let update_path =
        UpdatePath::tls_deserialize(&mut hex_to_bytes(&test_vector.update_path).as_slice())
            .expect("error deserializing");
    let group_context = hex_to_bytes(&test_vector.update_group_context);

    // Process the update_path to get a new root secret and update the tree.
    let mut diff = tree_before.empty_diff().expect("error creating diff");

    let (key_package, update_path_nodes) = update_path.into_parts();

    // Decrypt update path
    let decrypt_path_params = DecryptPathParams {
        version: ProtocolVersion::default(),
        update_path: update_path_nodes,
        sender_leaf_index: test_vector.update_sender,
        exclusion_list: &HashSet::new(),
        group_context: &group_context,
    };
    let (path, commit_secret) = diff
        .decrypt_path(backend, ciphersuite, decrypt_path_params)
        .expect("error decrypting update path");
    diff.apply_received_update_path(
        backend,
        ciphersuite,
        test_vector.update_sender,
        key_package,
        path,
    )
    .expect("error applying update path");

    let staged_diff = diff
        .into_staged_diff(backend, ciphersuite)
        .expect("error creating staged diff");
    tree_before
        .merge_diff(staged_diff)
        .expect("error merging diff after applying update path");

    // Rename to avoid confusion.
    let tree_after = tree_before;

    // We can't get hold of the root secret, but we can get hold of the commit
    // secret. So we're deriving the commit secret from the root secret given in
    // the kat here.
    let secret = Secret::from_slice(
        hex_to_bytes(&test_vector.root_secret_after_update).as_slice(),
        ProtocolVersion::default(),
        ciphersuite,
    );
    let path_secret: PathSecret = secret.into();
    let commit_secret_after_update_kat: CommitSecret = path_secret
        .derive_path_secret(backend, ciphersuite)
        .expect("error deriving commit secret")
        .into();

    // Verify that the new root root secret matches root_secret_after_update.
    if commit_secret_after_update_kat.as_slice() != commit_secret.as_slice() {
        if cfg!(test) {
            log::error!(
                "expected root secret: {}",
                test_vector.root_secret_after_update
            );
            log::error!(
                "got root secret:      {}",
                crate::test_utils::bytes_to_hex(commit_secret.as_slice())
            );
            panic!("Root secret mismatch in the 'after' tree.");
        }
        return Err(TreeKemTestVectorError::AfterRootSecretMismatch);
    }

    let ratchet_tree_after_bytes = hex_to_bytes(&test_vector.ratchet_tree_after);
    let ratchet_tree_after =
        TlsVecU32::<Option<Node>>::tls_deserialize(&mut ratchet_tree_after_bytes.as_slice())
            .expect("Error decoding ratchet tree");

    // Verify that the tree now matches tree_after
    if tree_after.export_nodes().as_slice() != ratchet_tree_after.as_slice() {
        if cfg!(test) {
            panic!("Ratchet tree mismatch in the after the update.");
        }
        return Err(TreeKemTestVectorError::AfterRatchetTreeMismatch);
    }

    // Verify that the tree hash of tree_after equals tree_hash_after.
    if hex_to_bytes(&test_vector.tree_hash_after) != tree_after.tree_hash() {
        if cfg!(test) {
            panic!("Tree hash mismatch in the 'after' tree.");
        }
        return Err(TreeKemTestVectorError::AfterTreeHashMismatch);
    }

    log::debug!("Done verifying TreeKEM test vector");

    Ok(())
}

#[apply(backends)]
fn read_test_vectors_tree_kem(backend: &impl OpenMlsCryptoProvider) {
    let tests: Vec<TreeKemTestVector> = read("test_vectors/kat_tree_kem_openmls.json");

    for test_vector in tests {
        run_test_vector(test_vector, backend).expect("error while checking tree kem test vector.");
    }
}

#[cfg(feature = "test-utils")]
/// TreeKem test vector error
#[derive(Error, Debug, PartialEq, Clone)]
pub enum TreeKemTestVectorError {
    /// Tree hash mismatch in the 'before' tree.
    #[error("Tree hash mismatch in the 'before' tree.")]
    BeforeTreeHashMismatch,
    /// Tree hash mismatch in the 'after' tree.
    #[error("Tree hash mismatch in the 'after' tree.")]
    AfterTreeHashMismatch,
    /// Parent hash mismatch in the 'before' tree.
    #[error("Parent hash mismatch in the 'before' tree.")]
    BeforeParentHashMismatch,
    /// Parent hash mismatch in the 'after' tree.
    #[error("Parent hash mismatch in the 'after' tree.")]
    AfterParentHashMismatch,
    /// Root secret mismatch in the 'before' tree.
    #[error("Root secret mismatch in the 'before' tree.")]
    BeforeRootSecretMismatch,
    /// Root secret mismatch in the 'after' tree.
    #[error("Root secret mismatch in the 'after' tree.")]
    AfterRootSecretMismatch,
    /// Ratchet tree mismatch in the after the update.
    #[error("Ratchet tree mismatch in the after the update.")]
    AfterRatchetTreeMismatch,
}
