//! TreeKEM test vectors
//!
//! See https://github.com/mlswg/mls-implementations/blob/master/test-vectors.md
//! for more description on the test vectors.
//!
//! The test vector describes a tree of `n` leaves adds a new leaf with
//! `my_key_package` and `my_path_secret` (common ancestor of `add_sender` and
//! `my_key_package`).
//! Then an update, sent by `update_sender` with `update_path` is processed, which
//! is processed by the newly added leaf as well.
//!
//! Some more points
//! * An empty group context is used.
//! * update path with empty exclusion list.

use crate::{
    ciphersuite::Ciphersuite,
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    extensions::{Extension, RatchetTreeExtension},
    key_packages::KeyPackageBundle,
    prelude::u32_range,
    test_util::{bytes_to_hex, hex_to_bytes, read, write},
    tree::{CiphersuiteName, Codec, HashSet, Node, NodeIndex, RatchetTree, SignatureScheme},
};

use serde::{self, Deserialize, Serialize};
use std::{cmp::min, convert::TryFrom};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TreeKemTestVector {
    cipher_suite: u16,

    // Chosen by the generator
    ratchet_tree_before: String,

    add_sender: u32,
    my_key_package: String,
    my_path_secret: String,

    update_sender: u32,
    update_path: String,

    // Computed values
    tree_hash_before: String,
    root_secret_after_add: String,
    root_secret_after_update: String,
    ratchet_tree_after: String,
    tree_hash_after: String,
}

fn create_identity(
    id: &[u8],
    ciphersuite_name: CiphersuiteName,
) -> (KeyPackageBundle, CredentialBundle) {
    let signature_scheme = SignatureScheme::from(ciphersuite_name);
    let credential_bundle =
        CredentialBundle::new(id.to_vec(), CredentialType::Basic, signature_scheme).unwrap();
    (
        KeyPackageBundle::new(&[ciphersuite_name], &credential_bundle, Vec::new()).unwrap(),
        credential_bundle,
    )
}

fn generate_test_vector(n_leaves: u32, ciphersuite: &'static Ciphersuite) -> TreeKemTestVector {
    // The key package bundle for add_sender
    let (kpb, cb) = create_identity(b"Tree creator", ciphersuite.name());

    // The new leaf key package
    let (my_kpb, _my_cb) = create_identity(b"Tree creator", ciphersuite.name());
    let my_key_package = my_kpb.key_package().clone();

    // The other key packages
    let mut nodes = Vec::new();
    let mut credentials = Vec::new();
    for leaf in 0..n_leaves - 1 {
        let (kpb_i, cb_i) = create_identity(&leaf.to_be_bytes(), ciphersuite.name());
        nodes.push(kpb_i);
        credentials.push(cb_i);
    }

    // The own index (must be even)
    let add_sender = u32_range(0..=n_leaves);
    let add_sender = if add_sender % 2 == 0 {
        add_sender
    } else {
        add_sender - 1
    };
    let update_sender = u32_range(0..=n_leaves);
    let update_sender = if update_sender % 2 == 0 {
        update_sender
    } else {
        update_sender - 1
    };

    // Initialise tree
    let mut tree = RatchetTree::init(ciphersuite);
    crate::utils::_print_tree(&tree, "Empty Tree");

    // Add leading nodes (before "self")
    let num_leading_nodes = (add_sender.saturating_sub(1)) as usize;
    nodes.iter().take(num_leading_nodes).for_each(|kpb| {
        let _ = tree.add_node(kpb.key_package());
    });
    crate::utils::_print_tree(&tree, "Tree with leading nodes");
    let (own_index, _own_cred) = tree.add_own_node(&kpb);
    crate::utils::_print_tree(&tree, "Tree with own node");

    let index = tree.own_node_index().as_u32();
    assert_eq!(
        own_index.as_u32(),
        NodeIndex::from(tree.own_node_index()).as_u32()
    );

    // Add the remaining nodes to the tree.
    // let key_packages: Vec<&KeyPackage> =
    nodes.iter().skip(index as usize).for_each(|kpb| {
        let _ = tree.add_node(kpb.key_package());
    });
    assert_eq!(tree.leaf_count().as_u32(), n_leaves);

    // Get and hash the tree before any operation.
    tree.all_parent_hashes();
    assert!(tree.verify_parent_hashes().is_ok());
    let ratchet_tree_before = tree.public_key_tree_copy();
    let ratchet_tree_extension =
        RatchetTreeExtension::new(ratchet_tree_before).to_extension_struct();
    let ratchet_tree_before_bytes = ratchet_tree_extension.extension_data();
    let tree_hash_before = tree.tree_hash();

    // Add the new leaf for my_key_package and get the path secret for it.
    let my_info = tree.add_nodes(&[&my_key_package]);
    crate::utils::_print_tree(&tree, "Tree with added node");
    let (my_node_index, _my_credential) = my_info.get(0).unwrap();
    let mut new_indices = HashSet::new();
    new_indices.insert(my_node_index);
    let (_path, _key_package_bundle) = tree.refresh_private_tree(&cb, &[], new_indices);
    let my_path_secret = tree.path_secret(*my_node_index).unwrap();
    let my_path_secret_bytes = my_path_secret.encode_detached().unwrap();
    let root_secret_after_add = tree.root_secret().unwrap();
    let root_secret_after_add_bytes = root_secret_after_add.encode_detached().unwrap();

    // `update_sender` updates the tree. We don't pick the `update_sender`
    // as index in the tree but something a little more convenient.
    // Because the tree implementation is so bad we have to create a new tree
    // here for `update_sender`.
    let (mut update_sender_tree, update_sender_cb) = if n_leaves == 1 || update_sender == index {
        (tree, &cb)
    } else {
        let old_tree: Vec<Option<Node>> = tree.nodes.iter().map(|n| Some(n.clone())).collect();
        let sender_index = min(update_sender as usize, credentials.len() - 1);
        let update_sender_cb = &credentials[sender_index];
        let update_sender_kpb = nodes.remove(sender_index);
        let new_tree =
            RatchetTree::new_from_nodes(ciphersuite, update_sender_kpb, &old_tree).unwrap();
        assert_eq!(tree.nodes, new_tree.nodes);
        (new_tree, update_sender_cb)
    };
    update_sender_tree.all_parent_hashes();
    crate::utils::_print_tree(&update_sender_tree, "Update sender tree");
    let (path, _key_package_bundle) =
        update_sender_tree.refresh_private_tree(update_sender_cb, &[], HashSet::new());
    let update_path = path.encode_detached().unwrap();
    let root_secret_after_update = update_sender_tree.root_secret().unwrap();
    let root_secret_after_update_bytes = root_secret_after_update.encode_detached().unwrap();
    assert!(update_sender_tree.verify_parent_hashes().is_ok());

    // Get and hash the tree after the operations.
    let ratchet_tree_after = update_sender_tree.public_key_tree_copy();
    let ratchet_tree_extension =
        RatchetTreeExtension::new(ratchet_tree_after).to_extension_struct();
    let ratchet_tree_after_bytes = ratchet_tree_extension.extension_data();
    let tree_hash_after = update_sender_tree.tree_hash();

    TreeKemTestVector {
        cipher_suite: ciphersuite.name() as u16,
        ratchet_tree_before: bytes_to_hex(&ratchet_tree_before_bytes),
        add_sender,
        my_key_package: bytes_to_hex(&my_key_package.encode_detached().unwrap()),
        my_path_secret: bytes_to_hex(&my_path_secret_bytes),
        update_sender,
        update_path: bytes_to_hex(&update_path),
        tree_hash_before: bytes_to_hex(&tree_hash_before),
        root_secret_after_add: bytes_to_hex(&root_secret_after_add_bytes),
        root_secret_after_update: bytes_to_hex(&root_secret_after_update_bytes),
        ratchet_tree_after: bytes_to_hex(ratchet_tree_after_bytes),
        tree_hash_after: bytes_to_hex(&tree_hash_after),
    }
}

#[test]
fn generate_test_vectors() {
    let mut tests = Vec::new();
    const NUM_LEAVES: u32 = 2;

    for ciphersuite in Config::supported_ciphersuites() {
        for n_leaves in 1..=NUM_LEAVES {
            println!(" Creating test case with {:?} leaves ...", n_leaves);
            let test = generate_test_vector(n_leaves, ciphersuite);
            tests.push(test);
        }
    }

    write("test_vectors/kat_tree_kem_openmls-new.json", &tests);
}

#[test]
fn run_test_vectors() {
    let tests: Vec<TreeKemTestVector> = read("test_vectors/kat_tree_kem_openmls.json");

    for test_vector in tests {
        let ciphersuite =
            CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
        let ciphersuite = match Config::ciphersuite(ciphersuite) {
            Ok(cs) => cs,
            Err(_) => {
                println!(
                    "Unsupported ciphersuite {} in test vector. Skipping ...",
                    ciphersuite
                );
                continue;
            }
        };

        // Check tree hashes.
        let tree_extension_before =
            RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_before))
                .expect("Error decoding ratchet tree");
        let ratchet_tree_before = tree_extension_before.into_vector();
        let tree_before = RatchetTree::init_from_nodes(ciphersuite, &ratchet_tree_before);
        crate::utils::_print_tree(&tree_before, "Tree before");
        assert_eq!(
            hex_to_bytes(&test_vector.tree_hash_before),
            tree_before.tree_hash()
        );

        let tree_extension_after =
            RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_after))
                .expect("Error decoding ratchet tree");
        let ratchet_tree_after = tree_extension_after.into_vector();
        let tree_after = RatchetTree::init_from_nodes(ciphersuite, &ratchet_tree_after);
        crate::utils::_print_tree(&tree_after, "Tree after");
        assert_eq!(
            hex_to_bytes(&test_vector.tree_hash_after),
            tree_after.tree_hash()
        );

        // Verify parent hashes
        assert!(tree_before.verify_parent_hashes().is_ok());
        assert!(tree_after.verify_parent_hashes().is_ok());

        // Get test node
    }
}
