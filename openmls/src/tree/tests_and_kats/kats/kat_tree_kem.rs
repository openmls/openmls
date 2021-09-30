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

use crate::ciphersuite::Ciphersuite;
use crate::group::HandshakeMessageFormat;
#[cfg(test)]
use crate::test_utils::{read, write};
use crate::{
    ciphersuite::signable::Signable,
    credentials::{CredentialBundle, CredentialType},
    node::Node,
    prelude::KeyPackageBundlePayload,
    test_utils::hex_to_bytes,
};
use crate::{
    ciphersuite::Secret,
    config::Config,
    config::ProtocolVersion,
    key_packages::KeyPackage,
    messages::PathSecret,
    tree::{treemath::*, CiphersuiteName, HashSet, LeafIndex, NodeIndex, RatchetTree, UpdatePath},
};
use crate::{
    group::{ManagedGroupCallbacks, ManagedGroupConfig, MlsMessage, UpdatePolicy},
    prelude::MlsPlaintextContentType,
    test_utils::{
        bytes_to_hex,
        test_framework::{ActionType, ManagedTestSetup},
    },
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
    let mut start_secret: PathSecret =
        Secret::from(hex_to_bytes(&test_vector.my_path_secret).as_slice()).into();
    start_secret.config(ciphersuite, ProtocolVersion::default());
    tree_before
        .private_tree_mut()
        .continue_path_secrets(ciphersuite, start_secret, &path);

    // Check if the root secrets match up.
    let mut root_secret_after_add: PathSecret =
        Secret::from(hex_to_bytes(&test_vector.root_secret_after_add).as_slice()).into();
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
    let mut root_secret_after_update: PathSecret =
        Secret::from(hex_to_bytes(&test_vector.root_secret_after_update).as_slice()).into();
    root_secret_after_update.config(ciphersuite, ProtocolVersion::default());

    if &root_secret_after_update != root_secret_after {
        if cfg!(test) {
            log::error!(
                "expected root secret: {}",
                test_vector.root_secret_after_update
            );
            log::error!(
                "got root secret:      {}",
                crate::test_utils::bytes_to_hex(
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
    let tests: Vec<TreeKemTestVector> = read("test_vectors/kat_tree_kem_openmls.json");

    for test_vector in tests {
        run_test_vector(test_vector).expect("error while checking tree kem test vector.");
    }
}

#[test]
fn write_test_vector() {
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

#[cfg(any(feature = "test-utils", test))]
pub fn generate_test_vector(n_leaves: u32, ciphersuite: &'static Ciphersuite) -> TreeKemTestVector {
    use crate::extensions::RatchetTreeExtension;

    // The test really only makes sense with two or more leaves
    if n_leaves <= 1 {
        panic!("test vector can only be generated with two or more members")
    }
    // Set up a group with `n_leaves` members.
    let handshake_message_format = HandshakeMessageFormat::Plaintext;
    let update_policy = UpdatePolicy::default();
    let callbacks = ManagedGroupCallbacks::default();
    let managed_group_config = ManagedGroupConfig::new(
        handshake_message_format,
        update_policy,
        0,
        0,
        false, // use_ratchet_tree_extension
        callbacks,
    );
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
    log::trace!("remover id: {:?}", remover_id);
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
    let addee_id = setup
        .random_new_members_for_group(group, 1)
        .unwrap()
        .pop()
        .unwrap();
    log::trace!("adding member with id: {:?}", addee_id);

    let clients = setup.clients.borrow();
    let adder = clients.get(&adder_id).unwrap().borrow();

    // We add the test client manually, so that we can get a hold of the leaf secret.
    let addee = clients.get(&addee_id).unwrap().borrow();

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

    let ratchet_tree_before = RatchetTreeExtension::new(addee_group.export_ratchet_tree())
        .tls_serialize_detached()
        .expect("error serializing ratchet tree extension");

    let tree_hash_before = addee_group.tree_hash();

    drop(addee_groups);
    drop(addee);

    let mut updater_id = group.random_group_member();
    while updater_id == addee_id {
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
    let group_context = updater_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing group context");

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
    drop(updater_groups);
    drop(updater);
    drop(adder);
    drop(clients);

    setup
        .distribute_to_members(&updater_id, group, &message)
        .unwrap();

    // The update was sent, now we get the right state variables again
    let clients = setup.clients.borrow();
    let addee = clients.get(&addee_id).unwrap().borrow();
    let addee_groups = addee.groups.borrow();
    let addee_group = addee_groups.get(&group_id).unwrap();
    let mut tree = addee_group.export_ratchet_tree();

    let own_node = tree
        .drain(..)
        .find(|node_option| {
            if let Some(node) = node_option {
                if let Some(key_package) = node.key_package() {
                    if key_package.credential().identity() == &addee_id {
                        return true;
                    }
                }
            }
            false
        })
        .unwrap();

    let my_key_package_after = own_node.as_ref().unwrap().key_package().unwrap();

    assert_eq!(&my_key_package, my_key_package_after);

    let path_secrets_after_update = addee_group.export_path_secrets();
    let root_secret_after_update = path_secrets_after_update.last().unwrap();

    let ratchet_tree_after = RatchetTreeExtension::new(addee_group.export_ratchet_tree())
        .tls_serialize_detached()
        .expect("error serializing ratchet tree extension");
    let tree_hash_after = addee_group.tree_hash();

    TreeKemTestVector {
        cipher_suite: ciphersuite.name() as u16,

        // Chosen by the generator
        ratchet_tree_before: bytes_to_hex(&ratchet_tree_before),

        add_sender: adder_index as u32,
        my_leaf_secret: bytes_to_hex(&my_leaf_secret.as_slice()),

        my_key_package: bytes_to_hex(
            &my_key_package
                .tls_serialize_detached()
                .expect("error serializing key package"),
        ),
        my_path_secret: bytes_to_hex(&my_path_secret.path_secret.as_slice()),

        // Computed values
        update_sender: updater_index as u32,
        update_path: bytes_to_hex(
            &update_path
                .tls_serialize_detached()
                .expect("error serializing update path"),
        ),
        update_group_context: bytes_to_hex(&group_context),
        tree_hash_before: bytes_to_hex(&tree_hash_before),
        root_secret_after_add: bytes_to_hex(&root_secret_after_add.path_secret.as_slice()),
        root_secret_after_update: bytes_to_hex(&root_secret_after_update.path_secret.as_slice()),
        ratchet_tree_after: bytes_to_hex(&ratchet_tree_after),
        tree_hash_after: bytes_to_hex(&tree_hash_after),
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
