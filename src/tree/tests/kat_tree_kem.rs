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
    ciphersuite::Secret,
    config::Config,
    config::ProtocolVersion,
    credentials::{CredentialBundle, CredentialType},
    extensions::ExtensionType,
    extensions::{Extension, RatchetTreeExtension},
    key_packages::KeyPackage,
    key_packages::KeyPackageBundle,
    messages::PathSecret,
    prelude::u32_range,
    test_util::{bytes_to_hex, hex_to_bytes, read, write},
    tree::treemath::*,
    tree::{
        CiphersuiteName, Codec, HashSet, LeafIndex, Node, NodeIndex, RatchetTree, SignatureScheme,
        UpdatePath,
    },
};

use serde::{self, Deserialize, Serialize};
use std::{cmp::min, convert::TryFrom};

#[derive(Serialize, Deserialize, Debug, Clone)]
struct TreeKemTestVector {
    cipher_suite: u16,

    // Chosen by the generator
    ratchet_tree_before: String,

    add_sender: u32,
    my_leaf_secret: String,
    my_key_package: String,
    my_path_secret: String,

    update_sender: u32,
    update_path: String,
    update_group_context: String,

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

#[test]
//#[cfg(test)]
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

        let tree_extension_before =
            RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_before))
                .expect("Error decoding ratchet tree");
        let ratchet_tree_before = tree_extension_before.into_vector();

        let my_leaf_secret = Secret::from_slice(
            &hex_to_bytes(&test_vector.my_leaf_secret),
            ProtocolVersion::default(),
            ciphersuite,
        );

        let my_key_package =
            KeyPackage::decode_detached(&hex_to_bytes(&test_vector.my_key_package))
                .expect("failed to decode my_key_package from test vector.");
        let my_key_package_bundle =
            KeyPackageBundle::from_key_package_and_leaf_secret(&my_leaf_secret, &my_key_package);

        // Check tree hashes.
        let mut tree_before =
            RatchetTree::new_from_nodes(my_key_package_bundle, &ratchet_tree_before).unwrap();
        crate::utils::_print_tree(&tree_before, "Tree before");
        assert_eq!(
            hex_to_bytes(&test_vector.tree_hash_before),
            tree_before.tree_hash()
        );

        let tree_extension_after =
            RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_after))
                .expect("Error decoding ratchet tree");
        let ratchet_tree_after = tree_extension_after.into_vector();

        let my_key_package_bundle =
            KeyPackageBundle::from_key_package_and_leaf_secret(&my_leaf_secret, &my_key_package);
        let tree_after =
            RatchetTree::new_from_nodes(my_key_package_bundle, &ratchet_tree_after).unwrap();
        crate::utils::_print_tree(&tree_after, "Tree after");
        assert_eq!(
            hex_to_bytes(&test_vector.tree_hash_after),
            tree_after.tree_hash()
        );

        // Verify parent hashes
        assert!(tree_before.verify_parent_hashes().is_ok());
        assert!(tree_after.verify_parent_hashes().is_ok());

        // Initialize private portion of the RatchetTree
        let add_sender = test_vector.add_sender;
        println!(
            "Add sender index: {:?}",
            NodeIndex::from(LeafIndex::from(add_sender))
        );
        println!(
            "Test client index: {:?}",
            NodeIndex::from(tree_before.own_node_index())
        );
        println!(
            "Updater index: {:?}",
            NodeIndex::from(LeafIndex::from(test_vector.update_sender))
        );
        let common_ancestor = common_ancestor_index(
            NodeIndex::from(LeafIndex::from(add_sender)),
            NodeIndex::from(tree_before.own_node_index()),
        );
        println!("Common ancestor: {:?}", common_ancestor);
        let path = parent_direct_path(common_ancestor, tree_before.leaf_count()).unwrap();
        println!("path: {:?}", path);
        let start_secret = Secret::from_slice(
            &hex_to_bytes(&test_vector.my_path_secret),
            ProtocolVersion::default(),
            ciphersuite,
        )
        .into();
        tree_before
            .private_tree_mut()
            .continue_path_secrets(ciphersuite, start_secret, &path);

        // Check if the root secrets match up.
        assert_eq!(
            tree_before.root_secret().unwrap(),
            &Secret::from_slice(
                &hex_to_bytes(&test_vector.root_secret_after_add),
                ProtocolVersion::default(),
                ciphersuite
            )
            .into()
        );

        // Apply the update path
        let update_path =
            UpdatePath::decode_detached(&hex_to_bytes(&test_vector.update_path)).unwrap();
        println!("UpdatePath: {:?}", update_path);
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
        let root_secret_after = tree_after.root_secret().unwrap();

        assert_eq!(
            root_secret_after,
            &Secret::from_slice(
                &hex_to_bytes(&test_vector.root_secret_after_update),
                ProtocolVersion::default(),
                ciphersuite
            )
            .into()
        );

        let tree_extension_after =
            RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_after))
                .expect("Error decoding ratchet tree");
        let ratchet_tree_after = tree_extension_after.into_vector();

        assert_eq!(tree_after.public_key_tree_copy(), ratchet_tree_after);

        println!("\nDone running test\n");
    }
}
