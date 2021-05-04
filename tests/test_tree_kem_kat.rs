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

use openmls::{prelude::*, test_util::*, tree::tests::kat_tree_kem::TreeKemTestVector};

mod utils;
use utils::managed_utils::*;

#[test]
fn test_tree_kem_kat() {
    let mut tests = Vec::new();
    const NUM_LEAVES: u32 = 20;

    for ciphersuite in Config::supported_ciphersuites() {
        for n_leaves in 2..NUM_LEAVES {
            log::trace!(" Creating test vector with {:?} leaves ...", n_leaves);
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
    let setup = ManagedTestSetup::new(managed_group_config, n_leaves as usize);

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
    log::trace!("remover id: {:?}", remover_id);
    //let mut target_index = thread_rng().gen_range(0..n_leaves);
    //while remover_index == target_index {
    //    target_index = thread_rng().gen_range(0..n_leaves);
    //}
    log::trace!("target id: {:?}", target_id);

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
    log::trace!("adder id: {:?}", adder_id);
    let (adder_index, _) = group
        .members
        .iter()
        .find(|(_, id)| id == &adder_id)
        .unwrap()
        .clone();
    let addees = setup.random_new_members_for_group(group, 1).unwrap();
    log::trace!("adding member with id: {:?}", addees);

    let clients = setup.clients.borrow();
    let adder = clients.get(&adder_id).unwrap().borrow();

    // We add the test client manually, so that we can get a hold of the leaf secret.
    let addee = clients.get(&addees[0]).unwrap().borrow();

    let my_key_package = setup
        .get_fresh_key_package(&addee, &group.ciphersuite)
        .unwrap();

    let my_leaf_secret = addee.key_store.get_leaf_secret(&my_key_package.hash());

    let (messages, welcome) = adder
        .add_members(
            ActionType::Commit,
            &group.group_id,
            &[my_key_package.clone()],
        )
        .unwrap();

    // It's only going to be a single message, since we only add one member.
    setup
        .distribute_to_members(&adder.identity, group, &messages[0])
        .unwrap();

    setup.deliver_welcome(welcome.unwrap(), group).unwrap();

    let addee_groups = addee.groups.borrow();
    let addee_group = addee_groups.get(&group_id).unwrap();

    let path_secrets = addee_group.export_path_secrets();

    let root_secret_after_add = path_secrets.last().unwrap().clone();
    let my_path_secret = path_secrets.first().unwrap().clone();

    drop(path_secrets);

    let ratchet_tree_extension_before =
        RatchetTreeExtension::new(addee_group.export_ratchet_tree()).to_extension_struct();
    let ratchet_tree_before = ratchet_tree_extension_before.extension_data();

    let tree_hash_before = addee_group.tree_hash();

    drop(addee_group);
    drop(addee_groups);
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
    let mut updater_groups = updater.groups.borrow_mut();
    let updater_group = updater_groups.get_mut(&group_id).unwrap();
    let group_context = updater_group.export_group_context().serialized().to_vec();

    let (message, _) = updater_group.self_update(&updater.key_store, None).unwrap();

    let update_path = match message {
        MlsMessage::Plaintext(ref pt) => match pt.content() {
            MlsPlaintextContentType::Commit(commit) => commit.path().as_ref().unwrap().clone(),
            _ => panic!("The message should not be anything but a commit."),
        },
        _ => panic!("The message should not be a ciphertext."),
    };

    // Drop all the borrows as not to cause problems when having the setup
    // distribute to members.
    drop(updater_group);
    drop(updater_groups);
    drop(updater);
    drop(adder);
    drop(clients);

    setup
        .distribute_to_members(&updater_id, group, &message)
        .unwrap();

    // The update was sent, now we get the right state variables again
    let clients = setup.clients.borrow();
    let addee = clients.get(&addees[0]).unwrap().borrow();
    let addee_groups = addee.groups.borrow();
    let addee_group = addee_groups.get(&group_id).unwrap();
    let tree = addee_group.export_ratchet_tree();

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

    let path_secrets_after_update = addee_group.export_path_secrets();
    let root_secret_after_update = path_secrets_after_update.last().unwrap();
    //let root_secret_after_update = addee.export_root_secret(&group_id).unwrap();
    let ratchet_tree_extension_after =
        RatchetTreeExtension::new(addee_group.export_ratchet_tree()).to_extension_struct();
    let ratchet_tree_after = ratchet_tree_extension_after.extension_data();
    let tree_hash_after = addee_group.tree_hash();

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
