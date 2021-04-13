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

#[cfg(any(feature = "expose-test-vectors", test))]
use crate::test_util::{bytes_to_hex, hex_to_bytes};
#[cfg(test)]
use crate::test_util::{read, write};
#[cfg(any(feature = "expose-test-vectors", test))]
use crate::{
    ciphersuite::Secret,
    config::Config,
    config::ProtocolVersion,
    extensions::{Extension, RatchetTreeExtension},
    key_packages::KeyPackage,
    key_packages::KeyPackageBundle,
    messages::PathSecret,
    prelude::*,
    tree::{
        treemath::*, CiphersuiteName, Codec, HashSet, LeafIndex, NodeIndex, RatchetTree, UpdatePath,
    },
};

use crate::{ciphersuite::Ciphersuite, tree::tests::managed_utils::*};

use serde::{self, Deserialize, Serialize};
use std::convert::TryFrom;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TreeKemTestVector {
    pub cipher_suite: u16,

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

#[cfg(any(feature = "expose-test-vectors", test))]
pub fn run_test_vector(test_vector: TreeKemTestVector) -> Result<(), TreeKemTestVectorError> {
    let ciphersuite =
        CiphersuiteName::try_from(test_vector.cipher_suite).expect("Invalid ciphersuite");
    let ciphersuite = Config::ciphersuite(ciphersuite).expect("Invalid ciphersuite");

    let tree_extension_before =
        RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_before))
            .expect("Error decoding ratchet tree");
    let ratchet_tree_before = tree_extension_before.into_vector();

    let my_leaf_secret = Secret::from_slice(
        &hex_to_bytes(&test_vector.my_leaf_secret),
        ProtocolVersion::default(),
        ciphersuite,
    );

    let my_key_package = KeyPackage::decode_detached(&hex_to_bytes(&test_vector.my_key_package))
        .expect("failed to decode my_key_package from test vector.");
    let my_key_package_bundle =
        KeyPackageBundle::from_key_package_and_leaf_secret(&my_leaf_secret, &my_key_package);

    // Check tree hashes.
    let mut tree_before =
        RatchetTree::new_from_nodes(my_key_package_bundle, &ratchet_tree_before).unwrap();
    crate::utils::_print_tree(&tree_before, "Tree before");

    if hex_to_bytes(&test_vector.tree_hash_before) != tree_before.tree_hash() {
        if cfg!(test) {
            panic!("Tree hash mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeTreeHashMismatch);
    }

    let tree_extension_after =
        RatchetTreeExtension::new_from_bytes(&hex_to_bytes(&test_vector.ratchet_tree_after))
            .expect("Error decoding ratchet tree");
    let ratchet_tree_after = tree_extension_after.into_vector();

    let my_key_package_bundle =
        KeyPackageBundle::from_key_package_and_leaf_secret(&my_leaf_secret, &my_key_package);
    let tree_after =
        RatchetTree::new_from_nodes(my_key_package_bundle, &ratchet_tree_after).unwrap();
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
    let root_secret_after_add: &PathSecret = &Secret::from_slice(
        &hex_to_bytes(&test_vector.root_secret_after_add),
        ProtocolVersion::default(),
        ciphersuite,
    )
    .into();
    if root_secret_after_add != tree_before.root_secret().unwrap() {
        if cfg!(test) {
            panic!("Root secret mismatch in the 'before' tree.");
        }
        return Err(TreeKemTestVectorError::BeforeRootSecretMismatch);
    }

    // Apply the update path
    let update_path = UpdatePath::decode_detached(&hex_to_bytes(&test_vector.update_path)).unwrap();
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
    let root_secret_after_update: &PathSecret = &Secret::from_slice(
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
    let ratchet_tree_after = tree_extension_after.into_vector();

    if tree_after.public_key_tree_copy() != ratchet_tree_after {
        if cfg!(test) {
            panic!("Ratchet tree mismatch in the after the update.");
        }
        return Err(TreeKemTestVectorError::AfterRatchetTreeMismatch);
    }

    println!("\nDone running test\n");

    Ok(())
}

#[test]
fn read_test_vector() {
    let tests: Vec<TreeKemTestVector> = read("test_vectors/kat_tree_kem_openmls.json");

    for test_vector in tests {
        run_test_vector(test_vector).expect("error while checking tree kem test vector.");
    }
}

#[cfg(any(feature = "expose-test-vectors", test))]
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

#[test]
fn test_tree_kem_kat() {
    let mut tests = Vec::new();
    const NUM_LEAVES: u32 = 20;

    for ciphersuite in Config::supported_ciphersuites() {
        for n_leaves in 2..NUM_LEAVES {
            println!(" Creating test case with {:?} leaves ...", n_leaves);
            let test = generate_test_vector(n_leaves, ciphersuite);
            tests.push(test);
        }
    }

    write("test_vectors/kat_tree_kem_openmls-new.json", &tests);
}

#[cfg(any(feature = "expose-test-vectors", test))]
pub fn generate_test_vector(n_leaves: u32, ciphersuite: &'static Ciphersuite) -> TreeKemTestVector {
    // The test really only makes sense with two or more leaves
    if n_leaves <= 1 {
        panic!("test vector can only be generated with two or more members")
    }
    // Set up a group with `n_leaves` members.
    let handshake_message_format = HandshakeMessageFormat::Plaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config =
        ManagedGroupConfig::new(handshake_message_format, update_policy, 0, 0, callbacks);
    let setup = ManagedTestSetup::new(
        managed_group_config,
        ManagedClientConfig::default_tests(),
        n_leaves as usize + 10,
    );

    // - I am the client with key package `my_key_package`
    // - I was added by the client at leaf index add_sender
    // - I therefore need to initialize my own path with the `path_secret` at the correct index
    // - Then the client at `update_sender` sends an update with the given `update_path`
    // - I process that update

    // We now need to create a state, where a client is added to a random
    // position in the tree by another randomly chosen client.

    // To reach that state, we create a group of `n_leaves` members and remove a
    // member from a random position.
    let group_id = setup
        .create_random_group(n_leaves as usize, ciphersuite)
        .unwrap();

    let mut groups = setup.groups.borrow_mut();
    let group = groups.get_mut(&group_id).unwrap();
    let remover_id = group.random_group_member();
    let mut target_id = group.random_group_member();
    while remover_id == target_id {
        target_id = group.random_group_member();
    }
    //let remover_index = thread_rng().gen_range(0..n_leaves);
    println!("remover id: {:?}", remover_id);
    //let mut target_index = thread_rng().gen_range(0..n_leaves);
    //while remover_index == target_index {
    //    target_index = thread_rng().gen_range(0..n_leaves);
    //}
    println!("target id: {:?}", target_id);

    let (target_index, _) = group
        .members
        .iter()
        .find(|(_, id)| id == &target_id)
        .unwrap()
        .clone();

    setup
        .remove_clients_by_index(
            ActionType::Commit,
            group,
            &remover_id,
            &[target_index as usize],
        )
        .unwrap();

    // We then have the same client who removed the target add a fresh member.
    let adder_id = remover_id;
    println!("adder id: {:?}", adder_id);
    let (adder_index, _) = group
        .members
        .iter()
        .find(|(_, id)| id == &adder_id)
        .unwrap()
        .clone();
    let addees = setup.random_new_members_for_group(group, 1).unwrap();
    println!("adding member with id: {:?}", addees);

    let clients = setup.clients.borrow();
    let adder = clients.get(&adder_id).unwrap().borrow();

    // We add the test client manually, so that we can get a hold of the leaf secret.
    let addee = clients.get(&addees[0]).unwrap().borrow();

    let my_key_package = setup
        .get_fresh_key_package(&addee, &group.ciphersuite)
        .unwrap();

    let my_leaf_secret = addee.get_leaf_secret_from_store(&my_key_package.hash());

    let (messages, welcome) = adder
        .add_members(&group.group_id, &[my_key_package.clone()], true)
        .unwrap();

    setup
        .distribute_to_members(adder.identity(), group, &messages)
        .unwrap();

    setup.deliver_welcome(welcome, group).unwrap();

    let path_secrets = addee.export_path_secrets(&group_id).unwrap();

    let root_secret_after_add = path_secrets.last().unwrap();
    let my_path_secret = path_secrets.first().unwrap();

    let ratchet_tree_extension_before =
        RatchetTreeExtension::new(addee.export_ratchet_tree(&group_id).unwrap())
            .to_extension_struct();
    let ratchet_tree_before = ratchet_tree_extension_before.extension_data();

    let tree_hash_before = addee.tree_hash(&group_id).unwrap();

    drop(addee);

    let mut updater_id = group.random_group_member();
    while updater_id == addees[0] {
        updater_id = group.random_group_member();
    }

    let (updater_index, _) = group
        .members
        .iter()
        .find(|(_, id)| id == &updater_id)
        .unwrap()
        .clone();

    let updater = clients.get(&updater_id).unwrap().borrow();
    let group_context = updater
        .export_group_context(&group_id)
        .unwrap()
        .serialized()
        .to_vec();

    let (messages, _) = updater.self_update(&group_id, None).unwrap();

    let update_path = match messages.first().unwrap() {
        MLSMessage::Plaintext(pt) => match pt.content() {
            MLSPlaintextContentType::Commit(commit) => commit.path().as_ref().unwrap().clone(),
            _ => panic!("The message should not be anything but a commit."),
        },
        _ => panic!("The message should not be a ciphertext."),
    };

    // Drop all the borrows as not to cause problems when having the setup
    // distribute to members.
    drop(updater);
    drop(adder);
    drop(clients);

    setup
        .distribute_to_members(&updater_id, group, &messages)
        .unwrap();

    // The update was sent, now we get the right state variables again
    let clients = setup.clients.borrow();
    let addee = clients.get(&addees[0]).unwrap().borrow();
    let tree = addee.export_ratchet_tree(&group_id).unwrap();

    let my_key_package_after = tree
        .iter()
        .find(|node_option| {
            if let Some(node) = node_option {
                if let Some(key_package) = node.key_package() {
                    if key_package.credential().identity() == &addees[0] {
                        return true;
                    }
                }
            }
            return false;
        })
        .unwrap()
        .as_ref()
        .unwrap()
        .key_package()
        .unwrap()
        .clone();

    assert_eq!(my_key_package, my_key_package_after);

    let path_secrets_after_update = addee.export_path_secrets(&group_id).unwrap();
    let root_secret_after_update = path_secrets_after_update.last().unwrap();
    //let root_secret_after_update = addee.export_root_secret(&group_id).unwrap();
    let ratchet_tree_extension_after =
        RatchetTreeExtension::new(addee.export_ratchet_tree(&group_id).unwrap())
            .to_extension_struct();
    let ratchet_tree_after = ratchet_tree_extension_after.extension_data();
    let tree_hash_after = addee.tree_hash(&group_id).unwrap();

    TreeKemTestVector {
        cipher_suite: ciphersuite.name() as u16,

        // Chosen by the generator
        ratchet_tree_before: bytes_to_hex(&ratchet_tree_before),

        add_sender: adder_index as u32,
        my_leaf_secret: bytes_to_hex(&my_leaf_secret.as_slice()),

        my_key_package: bytes_to_hex(&my_key_package.encode_detached().unwrap()),
        my_path_secret: bytes_to_hex(&my_path_secret.path_secret.as_slice()),

        // Computed values
        update_sender: updater_index as u32,
        update_path: bytes_to_hex(&update_path.encode_detached().unwrap()),
        update_group_context: bytes_to_hex(&group_context),
        tree_hash_before: bytes_to_hex(&tree_hash_before),
        root_secret_after_add: bytes_to_hex(&root_secret_after_add.path_secret.as_slice()),
        root_secret_after_update: bytes_to_hex(&root_secret_after_update.path_secret.as_slice()),
        ratchet_tree_after: bytes_to_hex(&ratchet_tree_after),
        tree_hash_after: bytes_to_hex(&tree_hash_after),
    }
}
