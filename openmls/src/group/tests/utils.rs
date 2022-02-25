//! A framework to create integration tests of the "raw" core_group API.
//! # Test utils
//!
//! Most tests require to set up groups, clients, credentials, and identities.
//! This module implements helpers to do that.

use std::cell::RefCell;
use std::collections::HashMap;

use crate::{
    credentials::{errors::*, *},
    framing::*,
    group::*,
    key_packages::{errors::*, *},
    test_utils::*,
    *,
};
use ::rand::rngs::OsRng;
use ::rand::RngCore;
use openmls_traits::key_store::OpenMlsKeyStore;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Serialize;

/// Configuration of a client meant to be used in a test setup.
#[derive(Clone)]
pub(crate) struct TestClientConfig {
    /// Name of the client.
    pub(crate) name: &'static str,
    /// Ciphersuites supported by the client.
    pub(crate) ciphersuites: Vec<Ciphersuite>,
}

/// Configuration of a group meant to be used in a test setup.
pub(crate) struct TestGroupConfig {
    pub(crate) ciphersuite: Ciphersuite,
    pub(crate) config: CoreGroupConfig,
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
    pub(crate) credential_bundles: HashMap<Ciphersuite, CredentialBundle>,
    pub(crate) key_package_bundles: RefCell<Vec<KeyPackageBundle>>,
    pub(crate) group_states: RefCell<HashMap<GroupId, CoreGroup>>,
}

impl TestClient {
    pub(crate) fn find_key_package_bundle(
        &self,
        key_package: &KeyPackage,
        backend: &impl OpenMlsCryptoProvider,
    ) -> Option<KeyPackageBundle> {
        let mut key_package_bundles = self.key_package_bundles.borrow_mut();
        key_package_bundles
            .iter()
            .position(|x| {
                x.key_package().hash_ref(backend.crypto()) == key_package.hash_ref(backend.crypto())
            })
            .map(|index| key_package_bundles.remove(index))
    }
}

/// The state of a test setup, including the state of the clients and the
/// keystore, which holds the KeyPackages published by the clients.
pub(crate) struct TestSetup {
    pub(crate) _key_store: RefCell<HashMap<(&'static str, Ciphersuite), Vec<KeyPackage>>>,
    // Clippy has a hard time figuring this one out
    #[allow(dead_code)]
    pub clients: RefCell<HashMap<&'static str, RefCell<TestClient>>>,
}

/// The number of key packages that each client registers with the key store
/// upon initializing the test setup.
const KEY_PACKAGE_COUNT: usize = 10;

/// The setup function creates a set of groups and clients.
pub(crate) fn setup(config: TestSetupConfig, backend: &impl OpenMlsCryptoProvider) -> TestSetup {
    let mut test_clients: HashMap<&'static str, RefCell<TestClient>> = HashMap::new();
    let mut key_store: HashMap<(&'static str, Ciphersuite), Vec<KeyPackage>> = HashMap::new();
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
                backend,
            )
            .expect("An unexpected error occurred.");
            // Create a number of key packages.
            let mut key_packages = Vec::new();
            for _ in 0..KEY_PACKAGE_COUNT {
                let capabilities_extension = Extension::Capabilities(CapabilitiesExtension::new(
                    None,
                    Some(&[ciphersuite]),
                    None,
                    None,
                ));
                let lifetime_extension = Extension::LifeTime(LifetimeExtension::new(60));
                let mandatory_extensions: Vec<Extension> =
                    vec![capabilities_extension, lifetime_extension];
                let key_package_bundle: KeyPackageBundle = KeyPackageBundle::new(
                    &[ciphersuite],
                    &credential_bundle,
                    backend,
                    mandatory_extensions,
                )
                .expect("An unexpected error occurred.");
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
            .expect("An unexpected error occurred.")
            .borrow_mut();
        // Pull the inital member's KeyPackage from the key_store.
        let initial_key_package = key_store
            .remove(&(group_config.members[0].name, group_config.ciphersuite))
            .expect("An unexpected error occurred.")
            .pop()
            .expect("An unexpected error occurred.");
        // Figure out which KeyPackageBundle that key package corresponds to.
        let initial_key_package_bundle = initial_group_member
            .find_key_package_bundle(&initial_key_package, backend)
            .expect("An unexpected error occurred.");
        // Get the credential bundle corresponding to the ciphersuite.
        let initial_credential_bundle = initial_group_member
            .credential_bundles
            .get(&group_config.ciphersuite)
            .expect("An unexpected error occurred.");
        // Initialize the group state for the initial member.
        let core_group = CoreGroup::builder(
            GroupId::from_slice(&group_id.to_be_bytes()),
            initial_key_package_bundle,
        )
        .with_config(group_config.config)
        .build(backend)
        .expect("Error creating new CoreGroup");
        let mut proposal_list = Vec::new();
        let group_aad = b"";
        // Framing parameters
        let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);
        initial_group_member
            .group_states
            .borrow_mut()
            .insert(core_group.context().group_id().clone(), core_group);
        // If there is more than one member in the group, prepare proposals and
        // commit. Then distribute the Welcome message to the new
        // members.
        if group_config.members.len() > 1 {
            let mut group_states = initial_group_member.group_states.borrow_mut();
            let core_group = group_states
                .get_mut(&GroupId::from_slice(&group_id.to_be_bytes()))
                .expect("An unexpected error occurred.");
            for client_id in 1..group_config.members.len() {
                // Pull a KeyPackage from the key_store for the new member.
                let next_member_key_package = key_store
                    .get_mut(&(
                        group_config.members[client_id].name,
                        group_config.ciphersuite,
                    ))
                    .expect("An unexpected error occurred.")
                    .pop()
                    .expect("An unexpected error occurred.");
                // Have the initial member create an Add proposal using the new
                // KeyPackage.
                let add_proposal = core_group
                    .create_add_proposal(
                        framing_parameters,
                        initial_credential_bundle,
                        next_member_key_package,
                        backend,
                    )
                    .expect("An unexpected error occurred.");
                proposal_list.push(add_proposal);
            }
            // Create the commit based on the previously compiled list of
            // proposals.
            let mut proposal_store = ProposalStore::new();
            for proposal in proposal_list {
                proposal_store.add(
                    QueuedProposal::from_mls_plaintext(group_config.ciphersuite, backend, proposal)
                        .expect("Could not create staged proposal."),
                );
            }
            let params = CreateCommitParams::builder()
                .framing_parameters(framing_parameters)
                .credential_bundle(initial_credential_bundle)
                .proposal_store(&proposal_store)
                .build();
            let create_commit_result = core_group
                .create_commit(params, backend)
                .expect("An unexpected error occurred.");
            let welcome = create_commit_result
                .welcome_option
                .expect("An unexpected error occurred.");

            core_group
                .merge_staged_commit(create_commit_result.staged_commit, &mut proposal_store)
                .expect("error merging own commits");

            // Distribute the Welcome message to the other members.
            for client_id in 1..group_config.members.len() {
                let new_group_member = test_clients
                    .get(group_config.members[client_id].name)
                    .expect("An unexpected error occurred.")
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
                            .any(|y| {
                                y.key_package()
                                    .hash_ref(backend.crypto())
                                    .expect("Could not hash KeyPackage.")
                                    == x.new_member()
                            })
                    })
                    .expect("An unexpected error occurred.");
                let kpb_position = new_group_member
                    .key_package_bundles
                    .borrow()
                    .iter()
                    .position(|y| {
                        y.key_package()
                            .hash_ref(backend.crypto())
                            .expect("Could not hash KeyPackage.")
                            == member_secret.new_member()
                    })
                    .expect("An unexpected error occurred.");
                let key_package_bundle = new_group_member
                    .key_package_bundles
                    .borrow_mut()
                    .remove(kpb_position);
                // Create the local group state of the new member based on the
                // Welcome.
                let new_group = match CoreGroup::new_from_welcome(
                    welcome.clone(),
                    Some(core_group.treesync().export_nodes()),
                    key_package_bundle,
                    backend,
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

/// No crypto randomness!
pub fn randombytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    OsRng.fill_bytes(&mut out);
    out
}

#[test]
fn test_random() {
    random_usize();
    randombytes(0);
}

#[apply(backends)]
fn test_setup(backend: &impl OpenMlsCryptoProvider) {
    let test_client_config_a = TestClientConfig {
        name: "TestClientConfigA",
        ciphersuites: vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
    };
    let test_client_config_b = TestClientConfig {
        name: "TestClientConfigB",
        ciphersuites: vec![Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
    };
    let group_config = CoreGroupConfig::default();
    let test_group_config = TestGroupConfig {
        ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
        config: group_config,
        members: vec![test_client_config_a.clone(), test_client_config_b.clone()],
    };
    let test_setup_config = TestSetupConfig {
        clients: vec![test_client_config_a, test_client_config_b],
        groups: vec![test_group_config],
    };
    let _test_setup = setup(test_setup_config, backend);
}

// Helper function to generate a CredentialBundle
pub(super) fn generate_credential_bundle(
    identity: Vec<u8>,
    credential_type: CredentialType,
    signature_scheme: SignatureScheme,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<Credential, CredentialError> {
    let cb = CredentialBundle::new(identity, credential_type, signature_scheme, backend)?;
    let credential = cb.credential().clone();
    backend
        .key_store()
        .store(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
            &cb,
        )
        .expect("An unexpected error occurred.");
    Ok(credential)
}

// Helper function to generate a KeyPackageBundle
pub(super) fn generate_key_package_bundle(
    ciphersuites: &[Ciphersuite],
    credential: &Credential,
    extensions: Vec<Extension>,
    backend: &impl OpenMlsCryptoProvider,
) -> Result<KeyPackage, KeyPackageBundleNewError> {
    let credential_bundle = backend
        .key_store()
        .read(
            &credential
                .signature_key()
                .tls_serialize_detached()
                .expect("Error serializing signature key."),
        )
        .expect("An unexpected error occurred.");
    let kpb = KeyPackageBundle::new(ciphersuites, &credential_bundle, backend, extensions)?;
    let kp = kpb.key_package().clone();
    backend
        .key_store()
        .store(
            kp.hash_ref(backend.crypto())
                .expect("Could not hash KeyPackage.")
                .value(),
            &kpb,
        )
        .expect("An unexpected error occurred.");
    Ok(kp)
}
