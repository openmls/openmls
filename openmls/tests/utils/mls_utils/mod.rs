//! # Test utils
//!
//! Most tests require to set up groups, clients, credentials, and identities.
//! This module implements helpers to do that.

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
    pub(crate) config: MlsGroupConfig,
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

impl TestClient {
    pub(crate) fn find_key_package_bundle(
        &self,
        key_package: &KeyPackage,
    ) -> Option<KeyPackageBundle> {
        let mut key_package_bundles = self.key_package_bundles.borrow_mut();
        key_package_bundles
            .iter()
            .position(|x| x.key_package().hash() == key_package.hash())
            .map(|index| key_package_bundles.remove(index))
    }
}

/// The state of a test setup, including the state of the clients and the
/// keystore, which holds the KeyPackages published by the clients.
pub(crate) struct TestSetup {
    pub(crate) _key_store: RefCell<HashMap<(&'static str, CiphersuiteName), Vec<KeyPackage>>>,
    pub clients: RefCell<HashMap<&'static str, RefCell<TestClient>>>,
}

/// The number of key packages that each client registers with the key store
/// upon initializing the test setup.
const KEY_PACKAGE_COUNT: usize = 10;

/// The setup function creates a set of groups and clients.
pub(crate) fn setup(config: TestSetupConfig) -> TestSetup {
    let mut test_clients: HashMap<&'static str, RefCell<TestClient>> = HashMap::new();
    let mut key_store: HashMap<(&'static str, CiphersuiteName), Vec<KeyPackage>> = HashMap::new();
    // Initialize the clients for which we have configurations.
    for client in config.clients {
        // Set up the client
        let mut credential_bundles = HashMap::new();
        let mut key_package_bundles = Vec::new();
        // This currently creates a credential bundle per ciphersuite, (not per
        // signature scheme), as well as 10 KeyPackages per ciphersuite.
        for ciphersuite in client.ciphersuites {
            // Create a credential_bundle for the given ciphersuite.
            let credential_bundle = CredentialBundle::new(
                client.name.as_bytes().to_vec(),
                CredentialType::Basic,
                SignatureScheme::from(ciphersuite),
            )
            .unwrap();
            // Create a number of key packages.
            let mut key_packages = Vec::new();
            for _ in 0..KEY_PACKAGE_COUNT {
                let capabilities_extension =
                    Box::new(CapabilitiesExtension::new(None, Some(&[ciphersuite]), None));
                let lifetime_extension = Box::new(LifetimeExtension::new(60));
                let mandatory_extensions: Vec<Box<dyn Extension>> =
                    vec![capabilities_extension, lifetime_extension];
                let key_package_bundle: KeyPackageBundle =
                    KeyPackageBundle::new(&[ciphersuite], &credential_bundle, mandatory_extensions)
                        .unwrap();
                key_packages.push(key_package_bundle.key_package().clone());
                key_package_bundles.push(key_package_bundle);
            }
            // Register the freshly created KeyPackages in the KeyStore.
            key_store.insert((client.name, ciphersuite), key_packages);
            // Store the credential bundle.
            credential_bundles.insert(ciphersuite, credential_bundle);
        }
        // Create the client.
        let test_client = TestClient {
            credential_bundles,
            key_package_bundles: RefCell::new(key_package_bundles),
            group_states: RefCell::new(HashMap::new()),
        };
        test_clients.insert(client.name, RefCell::new(test_client));
    }
    // Initialize all of the groups, each group gets assigned a sequential group
    // id. TODO: Depending on the use case, it might be hard to figure out which
    // group is which.
    for group_id in 0..config.groups.len() {
        let group_config = &config.groups[group_id];
        // The first party in the members array is going to be the group
        // initiator.
        let initial_group_member = test_clients
            .get(group_config.members[0].name)
            .unwrap()
            .borrow_mut();
        // Pull the inital member's KeyPackage from the key_store.
        let initial_key_package = key_store
            .remove(&(group_config.members[0].name, group_config.ciphersuite))
            .unwrap()
            .pop()
            .unwrap();
        // Figure out which KeyPackageBundle that key package corresponds to.
        let initial_key_package_bundle = initial_group_member
            .find_key_package_bundle(&initial_key_package)
            .unwrap();
        // Get the credential bundle corresponding to the ciphersuite.
        let initial_credential_bundle = initial_group_member
            .credential_bundles
            .get(&group_config.ciphersuite)
            .unwrap();
        // Initialize the group state for the initial member.
        let mls_group = MlsGroup::new(
            &group_id.to_be_bytes(),
            group_config.ciphersuite,
            initial_key_package_bundle,
            group_config.config,
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .unwrap();
        let mut proposal_list = Vec::new();
        let group_aad = b"";
        initial_group_member
            .group_states
            .borrow_mut()
            .insert(mls_group.context().group_id().clone(), mls_group);
        // If there is more than one member in the group, prepare proposals and
        // commit. Then distribute the Welcome message to the new
        // members.
        if group_config.members.len() > 1 {
            let mut group_states = initial_group_member.group_states.borrow_mut();
            let mls_group = group_states
                .get_mut(&GroupId::from_slice(&group_id.to_be_bytes()))
                .unwrap();
            for client_id in 1..group_config.members.len() {
                // Pull a KeyPackage from the key_store for the new member.
                let next_member_key_package = key_store
                    .get_mut(&(
                        group_config.members[client_id].name,
                        group_config.ciphersuite,
                    ))
                    .unwrap()
                    .pop()
                    .unwrap();
                // Have the initial member create an Add proposal using the new
                // KeyPackage.
                let add_proposal = mls_group
                    .create_add_proposal(
                        group_aad,
                        initial_credential_bundle,
                        next_member_key_package,
                    )
                    .unwrap();
                proposal_list.push(add_proposal);
            }
            // Create the commit based on the previously compiled list of
            // proposals.
            let (commit_mls_plaintext, welcome_option, key_package_bundle_option) = mls_group
                .create_commit(
                    group_aad,
                    &initial_credential_bundle,
                    &(proposal_list.iter().collect::<Vec<&MlsPlaintext>>()),
                    &[],
                    true, /* Set this to true to populate the tree a little bit. */
                    None, /* PSKs are not supported here */
                )
                .unwrap();
            let welcome = welcome_option.unwrap();
            let key_package_bundle = key_package_bundle_option.unwrap();
            // Apply the commit to the initial group member's group state using
            // the key package bundle returned by the create_commit earlier.
            match mls_group.apply_commit(
                &commit_mls_plaintext,
                &(proposal_list.iter().collect::<Vec<&MlsPlaintext>>()),
                &[key_package_bundle],
                None,
            ) {
                Ok(_) => (),
                Err(err) => panic!("Error applying Commit: {:?}", err),
            }
            // Distribute the Welcome message to the other members.
            for client_id in 1..group_config.members.len() {
                let new_group_member = test_clients
                    .get(group_config.members[client_id].name)
                    .unwrap()
                    .borrow_mut();
                // Figure out which key package bundle we should use. This is
                // a bit ugly and inefficient.
                let member_secret = welcome
                    .secrets()
                    .iter()
                    .find(|x| {
                        new_group_member
                            .key_package_bundles
                            .borrow()
                            .iter()
                            .any(|y| y.key_package().hash() == x.key_package_hash)
                    })
                    .unwrap();
                let kpb_position = new_group_member
                    .key_package_bundles
                    .borrow()
                    .iter()
                    .position(|y| y.key_package().hash() == member_secret.key_package_hash)
                    .unwrap();
                let key_package_bundle = new_group_member
                    .key_package_bundles
                    .borrow_mut()
                    .remove(kpb_position);
                // Create the local group state of the new member based on the
                // Welcome.
                let new_group = match MlsGroup::new_from_welcome(
                    welcome.clone(),
                    Some(mls_group.tree().public_key_tree_copy()),
                    key_package_bundle,
                    None, /* PSKs not supported here */
                ) {
                    Ok(group) => group,
                    Err(err) => panic!("Error creating new group from Welcome: {:?}", err),
                };

                new_group_member
                    .group_states
                    .borrow_mut()
                    .insert(new_group.group_id().clone(), new_group);
            }
        }
    }
    TestSetup {
        _key_store: RefCell::new(key_store),
        clients: RefCell::new(test_clients),
    }
}

pub fn random_usize() -> usize {
    OsRng.next_u64() as usize
}

pub fn randombytes(n: usize) -> Vec<u8> {
    random_vec(n)
}

#[test]
fn test_random() {
    random_usize();
    randombytes(0);
}

#[test]
fn test_setup() {
    let test_client_config_a = TestClientConfig {
        name: "TestClientConfigA",
        ciphersuites: vec![CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
    };
    let test_client_config_b = TestClientConfig {
        name: "TestClientConfigB",
        ciphersuites: vec![CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
    };
    let group_config = MlsGroupConfig::default();
    let test_group_config = TestGroupConfig {
        ciphersuite: CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        config: group_config,
        members: vec![test_client_config_a.clone(), test_client_config_b.clone()],
    };
    let test_setup_config = TestSetupConfig {
        clients: vec![test_client_config_a, test_client_config_b],
        groups: vec![test_group_config],
    };
    let _test_setup = setup(test_setup_config);
}
