//! A framework to create integration tests of the MlsGroup API.
//! # Test utils
//!
//! Most tests require to set up groups, clients, credentials, and identities.
//! This module implements helpers to do that.

use std::{cell::RefCell, collections::HashMap};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::SignatureScheme};
use rand::{rngs::OsRng, RngCore};
use tls_codec::Serialize;

use crate::{
    ciphersuite::signable::Signable, credentials::*, framing::*, group::*, key_packages::*,
    messages::ConfirmationTag, test_utils::*, *,
};

use self::storage::OpenMlsProvider;

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
    pub(crate) use_ratchet_tree_extension: bool,
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
    pub(crate) credentials: HashMap<Ciphersuite, CredentialWithKeyAndSigner>,
    pub(crate) group_states: RefCell<HashMap<GroupId, MlsGroup>>,
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
pub(crate) fn setup(
    config: TestSetupConfig,
    provider: &impl crate::storage::OpenMlsProvider,
) -> TestSetup {
    let mut test_clients: HashMap<&'static str, RefCell<TestClient>> = HashMap::new();
    let mut key_store: HashMap<(&'static str, Ciphersuite), Vec<KeyPackage>> = HashMap::new();
    // Initialize the clients for which we have configurations.
    for client in config.clients {
        // Set up the client
        let mut credentials = HashMap::new();
        let mut key_package_bundles = Vec::new();
        // This currently creates a credential with key per ciphersuite, (not per
        // signature scheme), as well as 10 KeyPackages per ciphersuite.
        for ciphersuite in client.ciphersuites {
            // Create a credential_with_key for the given ciphersuite.
            let credentia_with_key_and_signer = generate_credential_with_key(
                client.name.as_bytes().to_vec(),
                ciphersuite.signature_algorithm(),
                provider,
            );
            // Create a number of key packages.
            let mut key_packages = Vec::new();
            for _ in 0..KEY_PACKAGE_COUNT {
                let key_package_bundle: KeyPackageBundle = KeyPackageBundle::generate(
                    provider,
                    &credentia_with_key_and_signer.signer,
                    ciphersuite,
                    credentia_with_key_and_signer.credential_with_key.clone(),
                );
                key_packages.push(key_package_bundle.key_package().clone());
                key_package_bundles.push(key_package_bundle);
            }
            // Register the freshly created KeyPackages in the KeyStore.
            key_store.insert((client.name, ciphersuite), key_packages);
            // Store the credential and keys.
            credentials.insert(ciphersuite, credentia_with_key_and_signer);
        }
        // Create the client.
        let test_client = TestClient {
            credentials,
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
        // Get the credential with key corresponding to the ciphersuite.
        let credential_with_key_and_signer = initial_group_member
            .credentials
            .get(&group_config.ciphersuite)
            .expect("An unexpected error occurred.");
        // Initialize the group state for the initial member.
        let mls_group = MlsGroup::builder()
            .with_group_id(GroupId::from_slice(&group_id.to_be_bytes()))
            .ciphersuite(group_config.ciphersuite)
            .use_ratchet_tree_extension(group_config.use_ratchet_tree_extension)
            .with_wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
            .build(
                provider,
                &credential_with_key_and_signer.signer,
                credential_with_key_and_signer.credential_with_key.clone(),
            )
            .expect("Error creating group.");
        initial_group_member
            .group_states
            .borrow_mut()
            .insert(mls_group.group_id().clone(), mls_group);
        // If there is more than one member in the group, prepare proposals and
        // commit. Then distribute the Welcome message to the new
        // members.
        if group_config.members.len() > 1 {
            let mut group_states = initial_group_member.group_states.borrow_mut();
            let mls_group = group_states
                .get_mut(&GroupId::from_slice(&group_id.to_be_bytes()))
                .expect("An unexpected error occurred.");
            let mut key_packages = vec![];
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
                key_packages.push(next_member_key_package.clone());
            }
            // Create the commit based on the previously compiled list of
            // proposals.
            let (_commit, welcome, _) = mls_group
                .add_members(
                    provider,
                    &credential_with_key_and_signer.signer,
                    &key_packages,
                )
                .expect("An unexpected error occurred.");
            let welcome = welcome.into_welcome().unwrap();

            mls_group
                .merge_pending_commit(provider)
                .expect("Error merging commit.");

            let join_config = MlsGroupJoinConfig::builder()
                .wire_format_policy(PURE_CIPHERTEXT_WIRE_FORMAT_POLICY)
                .build();

            // Distribute the Welcome message to the other members.
            for client_id in 1..group_config.members.len() {
                let new_group_member = test_clients
                    .get(group_config.members[client_id].name)
                    .expect("An unexpected error occurred.")
                    .borrow_mut();
                // Create the local group state of the new member based on the
                // Welcome.
                let ratchet_tree = Some(mls_group.export_ratchet_tree().into());
                let new_group = StagedWelcome::new_from_welcome(
                    provider,
                    &join_config,
                    welcome.clone(),
                    ratchet_tree,
                )
                .unwrap()
                .into_group(provider)
                .unwrap();

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

#[openmls_test::openmls_test]
fn test_setup(provider: &impl crate::storage::OpenMlsProvider) {
    let test_client_config_a = TestClientConfig {
        name: "TestClientConfigA",
        ciphersuites: vec![Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519],
    };
    let test_client_config_b = TestClientConfig {
        name: "TestClientConfigB",
        ciphersuites: vec![Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519],
    };
    let use_ratchet_tree_extension = true;
    let test_group_config = TestGroupConfig {
        ciphersuite: Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
        use_ratchet_tree_extension,
        members: vec![test_client_config_a.clone(), test_client_config_b.clone()],
    };
    let test_setup_config = TestSetupConfig {
        clients: vec![test_client_config_a, test_client_config_b],
        groups: vec![test_group_config],
    };
    let _test_setup = setup(test_setup_config, provider);
}

#[derive(Clone)]
pub(crate) struct CredentialWithKeyAndSigner {
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) signer: SignatureKeyPair,
}

// Helper function to generate a CredentialWithKeyAndSigner
pub(crate) fn generate_credential_with_key<Provider: OpenMlsProvider>(
    identity: Vec<u8>,
    signature_scheme: SignatureScheme,
    provider: &Provider,
) -> CredentialWithKeyAndSigner {
    let (credential, signer) = {
        let credential = BasicCredential::new(identity);
        let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
        signature_keys.store(provider.storage()).unwrap();

        (credential, signature_keys)
    };
    let signature_key =
        OpenMlsSignaturePublicKey::new(signer.to_public_vec().into(), signature_scheme).unwrap();

    CredentialWithKeyAndSigner {
        credential_with_key: CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_key.into(),
        },
        signer,
    }
}

// Helper function to generate a KeyPackageBundle
pub(crate) fn generate_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    extensions: Extensions,
    provider: &Provider,
    credential_with_keys: CredentialWithKeyAndSigner,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(
            ciphersuite,
            provider,
            &credential_with_keys.signer,
            credential_with_keys.credential_with_key,
        )
        .unwrap()
}

#[cfg(test)]
pub(crate) fn resign_message(
    alice_group: &MlsGroup,
    plaintext: PublicMessage,
    original_plaintext: &PublicMessage,
    provider: &impl crate::storage::OpenMlsProvider,
    signer: &impl Signer,
    ciphersuite: Ciphersuite,
) -> PublicMessage {
    let serialized_context = alice_group
        .export_group_context()
        .tls_serialize_detached()
        .expect("error serializing context");

    // We have to re-sign, since we changed the content.
    let tbs: FramedContentTbs = plaintext.into();
    let mut signed_plaintext: AuthenticatedContent = tbs
        .with_context(serialized_context)
        .sign(signer)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    signed_plaintext.set_confirmation_tag(
        original_plaintext
            .confirmation_tag()
            .expect("no confirmation tag on original message")
            .clone(),
    );

    let mut signed_plaintext: PublicMessage = signed_plaintext.into();

    let membership_key = alice_group.message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(
            provider.crypto(),
            ciphersuite,
            membership_key,
            alice_group.message_secrets().serialized_context(),
        )
        .expect("error refreshing membership tag");
    signed_plaintext
}

#[cfg(test)]
pub(crate) fn resign_external_commit(
    signer: &impl Signer,
    public_message: PublicMessage,
    old_confirmation_tag: ConfirmationTag,
    serialized_context: Vec<u8>,
) -> PublicMessage {
    let tbs: FramedContentTbs = public_message.into();

    let mut public_message: AuthenticatedContent = tbs
        .with_context(serialized_context)
        .sign(signer)
        .expect("Error signing modified payload.");

    // Set old confirmation tag
    public_message.set_confirmation_tag(old_confirmation_tag);

    public_message.into()
}
