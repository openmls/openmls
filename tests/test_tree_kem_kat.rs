use openmls::{prelude::*, test_util::*};

mod utils;
use utils::managed_utils::*;

use rand::{thread_rng, Rng};

use serde::{self, Deserialize, Serialize};

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
fn generate_test_vector(n_leaves: u32, ciphersuite: &'static Ciphersuite) -> TreeKemTestVector {
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
    let setup = ManagedTestSetup::new(managed_group_config, n_leaves as usize + 10);
    setup.create_clients();

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
    let remover_index = thread_rng().gen_range(0..n_leaves);
    println!("remover index: {:?}", remover_index);
    let mut target_index = thread_rng().gen_range(0..n_leaves);
    while remover_index == target_index {
        target_index = thread_rng().gen_range(0..n_leaves);
    }
    println!("target index: {:?}", target_index);

    let (_, remover_id) = group
        .members
        .iter()
        .find(|(index, _)| index == &(remover_index as usize))
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
    let adder_index = remover_index;
    println!("adder index: {:?}", adder_index);
    let addees = setup.random_new_members_for_group(group, 1).unwrap();
    println!("adding member with id: {:?}", addees);

    let clients = setup.clients.borrow();
    let remover = clients.get(&remover_id).unwrap().borrow();
    let remover_groups = remover.groups.borrow();
    let group_state = remover_groups.get(&group_id).unwrap();

    group_state.print_tree("tree before adding");

    drop(remover_groups);

    // rename to avoid confusion
    let adder = remover;

    // We add the test client manually, so that we can get a hold of the leaf secret.
    let addee = clients.get(&addees[0]).unwrap().borrow();

    let my_key_package = setup
        .get_fresh_key_package(&addee, &group.ciphersuite)
        .unwrap();

    let addee_kpbs = addee.key_package_bundles.borrow();
    let my_leaf_secret = addee_kpbs
        .get(&my_key_package.hash())
        .unwrap()
        .get_leaf_secret();
    drop(addee_kpbs);

    let (messages, welcome_option) = adder
        .add_members(
            ActionType::Commit,
            &group.group_id,
            &[my_key_package.clone()],
            true,
        )
        .unwrap();
    setup
        .distribute_to_members(&adder.identity, group, &messages)
        .unwrap();
    if let Some(welcome) = welcome_option {
        setup.deliver_welcome(welcome, group).unwrap();
    }

    let addee_groups = addee.groups.borrow();
    let group_state = addee_groups.get(&group_id).unwrap();
    let path_secrets = group_state.export_path_secrets();

    let root_secret_after_add = path_secrets.last().unwrap();
    let my_path_secret = path_secrets.first().unwrap();

    let ratchet_tree_extension_before =
        RatchetTreeExtension::new(group_state.export_ratchet_tree()).to_extension_struct();
    let ratchet_tree_before = ratchet_tree_extension_before.extension_data();

    let tree_hash_before = group_state.tree_hash();

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
    let updater_group_state = updater_groups.get_mut(&group_id).unwrap();
    let group_context = updater_group_state
        .export_group_context()
        .serialized()
        .to_vec();

    let (messages, _) = updater_group_state.self_update(None).unwrap();

    let update_path = match messages.first().unwrap() {
        MLSMessage::Plaintext(pt) => match pt.content() {
            MLSPlaintextContentType::Commit(commit) => commit.path().as_ref().unwrap().clone(),
            _ => panic!("The message should not be anything but a commit."),
        },
        _ => panic!("The message should not be a ciphertext."),
    };

    // Drop all the borrows as not to cause problems when having the setup
    // distribute to members.
    drop(updater_groups);
    drop(updater);
    drop(adder);
    drop(clients);

    setup
        .distribute_to_members(&updater_id, group, &messages)
        .unwrap();

    // The update was sent, now we get the right state variables again
    let clients = setup.clients.borrow();
    let addee = clients.get(&addees[0]).unwrap().borrow();
    let addee_groups = addee.groups.borrow();
    let group_state = addee_groups.get(&group_id).unwrap();
    let tree = group_state.export_ratchet_tree();

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

    let root_secret_after_update = group_state.export_root_secret();
    let ratchet_tree_extension_after =
        RatchetTreeExtension::new(group_state.export_ratchet_tree()).to_extension_struct();
    let ratchet_tree_after = ratchet_tree_extension_after.extension_data();
    let tree_hash_after = group_state.tree_hash();

    TreeKemTestVector {
        cipher_suite: ciphersuite.name() as u16,

        // Chosen by the generator
        ratchet_tree_before: bytes_to_hex(&ratchet_tree_before),

        add_sender: adder_index,
        my_leaf_secret: bytes_to_hex(&my_leaf_secret.encode_detached().unwrap()),

        my_key_package: bytes_to_hex(&my_key_package.encode_detached().unwrap()),
        my_path_secret: bytes_to_hex(&my_path_secret.encode_detached().unwrap()),

        // Computed values
        update_sender: updater_index as u32,
        update_path: bytes_to_hex(&update_path.encode_detached().unwrap()),
        update_group_context: bytes_to_hex(&group_context),
        tree_hash_before: bytes_to_hex(&tree_hash_before),
        root_secret_after_add: bytes_to_hex(&root_secret_after_add.encode_detached().unwrap()),
        root_secret_after_update: bytes_to_hex(
            &root_secret_after_update.encode_detached().unwrap(),
        ),
        ratchet_tree_after: bytes_to_hex(&ratchet_tree_after),
        tree_hash_after: bytes_to_hex(&tree_hash_after),
    }
}
