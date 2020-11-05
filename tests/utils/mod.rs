//! # Test utils
//!
//! Most tests require to set up groups, clients, credentials, and identities.
//! This module implements helpers to do that.
//!

use std::cell::RefCell;
use std::collections::HashMap;

use evercrypt::prelude::*;
use openmls::prelude::*;
use rand::rngs::OsRng;
use rand::RngCore;

/// Configuration of a client meant to be used in a test setup.
#[derive(Clone)]
pub(crate) struct TestClientConfig {
    /// Name of the client.
    pub(crate) name: &'static str,
    /// Ciphersuites supported by the client.
    pub(crate) ciphersuites: Vec<CiphersuiteName>,
}

/// Configuration of a group meant to be used in a test setup.
pub(crate) struct TestGroupConfig {
    pub(crate) ciphersuite: CiphersuiteName,
    pub(crate) config: GroupConfig,
    pub(crate) members: Vec<TestClientConfig>,
}

/// Configuration of a test setup including clients and groups used in the test
/// setup.
pub(crate) struct TestSetupConfig {
    pub(crate) clients: Vec<TestClientConfig>,
    pub(crate) groups: Vec<TestGroupConfig>,
}

/// A client in a test setup.
pub(crate) struct TestClient {
    pub(crate) credential_bundles: HashMap<CiphersuiteName, CredentialBundle>,
    pub(crate) key_package_bundles: RefCell<Vec<KeyPackageBundle>>,
    pub(crate) group_states: RefCell<HashMap<GroupId, MlsGroup>>,
}

/// The state of a test setup, including the state of the clients and the
/// keystore, which holds the KeyPackages published by the clients.
pub(crate) struct TestSetup {
    pub(crate) key_store: RefCell<HashMap<(&'static str, CiphersuiteName), Vec<KeyPackage>>>,
    pub(crate) clients: RefCell<HashMap<&'static str, RefCell<TestClient>>>,
}

/// The setup function creates a set of groups and clients.
pub(crate) fn setup(config: TestSetupConfig) -> TestSetup {
    let mut test_clients: HashMap<&'static str, RefCell<TestClient>> = HashMap::new();
    let mut key_store: HashMap<(&'static str, CiphersuiteName), Vec<KeyPackage>> = HashMap::new();
    for client in config.clients {
        // Set up the client
        let mut credential_bundles = HashMap::new();
        let mut key_package_bundles = Vec::new();
        // This currently creates a credential bundle per ciphersuite, (not per
        // signature scheme), as well as 10 KeyPackages per ciphersuite.
        for ciphersuite in client.ciphersuites {
            //Initialize KeyStore for that client and ciphersuite.
            key_store.insert((client.name, ciphersuite), Vec::new());
            let credential_bundle = CredentialBundle::new(
                client.name.as_bytes().to_vec(),
                CredentialType::Basic,
                ciphersuite,
            )
            .unwrap();
            for _ in 0..10 {
                let key_package_bundle: KeyPackageBundle =
                    KeyPackageBundle::new(&[ciphersuite], &credential_bundle, Vec::new()).unwrap();
                // Register the freshly created KeyPackage in the KeyStore.
                key_store
                    .get_mut(&(client.name, ciphersuite))
                    .unwrap()
                    .push(key_package_bundle.get_key_package().clone());
                key_package_bundles.push(key_package_bundle);
            }
            credential_bundles.insert(ciphersuite, credential_bundle);
        }
        let test_client = TestClient {
            credential_bundles,
            key_package_bundles: RefCell::new(key_package_bundles),
            group_states: RefCell::new(HashMap::new()),
        };
        test_clients.insert(client.name, RefCell::new(test_client));
    }
    for group_id in 0..config.groups.len() {
        let group_config = &config.groups[group_id];
        // The first party in the members array is going to be the group
        // initiator. We remove it here and add it back later to avoid borrowing
        // issues.
        let initial_group_member = test_clients
            .get(group_config.members[0].name)
            .unwrap()
            .borrow_mut();
        let initial_key_package = key_store
            .remove(&(group_config.members[0].name, group_config.ciphersuite))
            .unwrap()
            .pop()
            .unwrap();
        let initial_key_package_bundle_position = initial_group_member
            .key_package_bundles
            .borrow()
            .iter()
            .position(|x| x.get_key_package().hash() == initial_key_package.hash())
            .unwrap();
        let initial_key_package_bundle = initial_group_member
            .key_package_bundles
            .borrow_mut()
            .remove(initial_key_package_bundle_position);
        let initial_credential_bundle = initial_group_member
            .credential_bundles
            .get(&group_config.ciphersuite)
            .unwrap();
        let mls_group = MlsGroup::new(
            &group_id.to_be_bytes(),
            group_config.ciphersuite,
            initial_key_package_bundle,
            group_config.config,
        )
        .unwrap();
        let mut proposal_list = Vec::new();
        let group_aad = b"";
        initial_group_member
            .group_states
            .borrow_mut()
            .insert(mls_group.context().group_id.clone(), mls_group);
        // If there is more than one member in the group, prepare proposals and
        // commit. Then distribute the Welcome and the commit to the other
        // members.
        if group_config.members.len() > 1 {
            let group_states = initial_group_member.group_states.borrow();
            let mls_group = group_states
                .get(&GroupId::from_slice(&group_id.to_be_bytes()))
                .unwrap();
            for client_id in 1..group_config.members.len() {
                let next_member_key_package = key_store
                    .get_mut(&(
                        group_config.members[client_id].name,
                        group_config.ciphersuite,
                    ))
                    .unwrap()
                    .pop()
                    .unwrap();
                let add_proposal = mls_group.create_add_proposal(
                    group_aad,
                    initial_credential_bundle,
                    next_member_key_package,
                );
                proposal_list.push(add_proposal);
            }
            let (commit_mls_plaintext, welcome_option, _key_package_bundle_option) = mls_group
                .create_commit(
                    group_aad,
                    &initial_credential_bundle,
                    proposal_list.clone(),
                    false,
                )
                .unwrap();
            let welcome = welcome_option.unwrap();
            // Distribute the Welcome message to the other members.
            for client_id in 1..group_config.members.len() {
                let new_group_member = test_clients
                    .get(group_config.members[client_id].name)
                    .unwrap()
                    .borrow_mut();
                // Figure out which key package bundle we should use. This is
                // very ugly and inefficient.
                let member_secret = welcome
                    .get_secrets_ref()
                    .iter()
                    .find(|x| {
                        match new_group_member
                            .key_package_bundles
                            .borrow()
                            .iter()
                            .find(|y| y.get_key_package().hash() == x.key_package_hash)
                        {
                            Some(_) => true,
                            None => false,
                        }
                    })
                    .unwrap();
                let kpb_position = new_group_member
                    .key_package_bundles
                    .borrow()
                    .iter()
                    .position(|y| y.get_key_package().hash() == member_secret.key_package_hash)
                    .unwrap();
                let key_package_bundle = new_group_member
                    .key_package_bundles
                    .borrow_mut()
                    .remove(kpb_position);
                let new_group =
                    MlsGroup::new_from_welcome(welcome.clone(), None, key_package_bundle).unwrap();
                new_group_member
                    .group_states
                    .borrow_mut()
                    .insert(new_group.context().group_id.clone(), new_group);
            }
            // Make all members receive and process the commit message.
            for member in &group_config.members {
                let group_member = test_clients.get(member.name).unwrap().borrow();
                let key_package_bundles = group_member.key_package_bundles.borrow();
                let mut group_states = group_member.group_states.borrow_mut();
                let group = group_states
                    .get_mut(&commit_mls_plaintext.group_id.clone())
                    .unwrap();
                let _ = group.apply_commit(
                    commit_mls_plaintext.clone(),
                    proposal_list.clone(),
                    &key_package_bundles,
                );
            }
        }
    }
    TestSetup {
        key_store: RefCell::new(key_store),
        clients: RefCell::new(test_clients),
    }
}

pub(crate) fn random_usize() -> usize {
    OsRng.next_u64() as usize
}

pub(crate) fn randombytes(n: usize) -> Vec<u8> {
    get_random_vec(n)
}

// Not currently used.
//pub(crate) fn hex_to_bytes(hex: &str) -> Vec<u8> {
//    let mut bytes = Vec::new();
//    for i in 0..(hex.len() / 2) {
//        let b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
//        bytes.push(b);
//    }
//    bytes
//}
