//! A framework to create integration tests of the "raw" core_group API.
//! # Test utils
//!
//! Most tests require to set up groups, clients, credentials, and identities.
//! This module implements helpers to do that.

use std::{cell::RefCell, collections::HashMap};

use config::CryptoConfig;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::{
    key_store::OpenMlsKeyStore, signatures::Signer, types::SignatureScheme, OpenMlsProvider,
};
use rand::{rngs::OsRng, RngCore};
use tls_codec::Serialize;

use crate::{
    ciphersuite::signable::Signable, credentials::*, framing::*, group::*, key_packages::*,
    messages::ConfirmationTag, schedule::psk::store::ResumptionPskStore, test_utils::*,
    versions::ProtocolVersion, *,
};

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
    pub(crate) credentials: HashMap<Ciphersuite, CredentialWithKeyAndSigner>,
    pub(crate) key_package_bundles: RefCell<Vec<KeyPackageBundle>>,
    pub(crate) group_states: RefCell<HashMap<GroupId, CoreGroup>>,
}

impl TestClient {
    pub(crate) fn find_key_package_bundle(
        &self,
        key_package: &KeyPackage,
        crypto: &impl OpenMlsCrypto,
    ) -> Option<KeyPackageBundle> {
        let mut key_package_bundles = self.key_package_bundles.borrow_mut();
        key_package_bundles
            .iter()
            .position(|x| x.key_package().hash_ref(crypto) == key_package.hash_ref(crypto))
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
pub(crate) fn setup(config: TestSetupConfig, provider: &impl OpenMlsProvider) -> TestSetup {
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
                let key_package_bundle: KeyPackageBundle = KeyPackageBundle::new(
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
        // Get the credential with key corresponding to the ciphersuite.
        let credential_with_key_and_signer = initial_group_member
            .credentials
            .get(&group_config.ciphersuite)
            .expect("An unexpected error occurred.");
        // Initialize the group state for the initial member.
        let core_group = CoreGroup::builder(
            GroupId::from_slice(&group_id.to_be_bytes()),
            CryptoConfig::with_default_version(group_config.ciphersuite),
            credential_with_key_and_signer.credential_with_key.clone(),
        )
        .with_config(group_config.config)
        .build(provider, &credential_with_key_and_signer.signer)
        .expect("Error creating new CoreGroup");
        let mut proposal_list = Vec::new();
        let group_aad = b"";
        // Framing parameters
        let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);
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
                        next_member_key_package,
                        &credential_with_key_and_signer.signer,
                    )
                    .expect("An unexpected error occurred.");
                proposal_list.push(add_proposal);
            }
            // Create the commit based on the previously compiled list of
            // proposals.
            let mut proposal_store = ProposalStore::new();
            for proposal in proposal_list {
                proposal_store.add(
                    QueuedProposal::from_authenticated_content_by_ref(
                        group_config.ciphersuite,
                        provider.crypto(),
                        proposal,
                    )
                    .expect("Could not create staged proposal."),
                );
            }
            let params = CreateCommitParams::builder()
                .framing_parameters(framing_parameters)
                .proposal_store(&proposal_store)
                .build();
            let create_commit_result = core_group
                .create_commit(params, provider, &credential_with_key_and_signer.signer)
                .expect("An unexpected error occurred.");
            let welcome = create_commit_result
                .welcome_option
                .expect("An unexpected error occurred.");

            core_group
                .merge_staged_commit(
                    provider,
                    create_commit_result.staged_commit,
                    &mut proposal_store,
                )
                .expect("Error merging commit.");

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
                                    .hash_ref(provider.crypto())
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
                            .hash_ref(provider.crypto())
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
                    Some(core_group.public_group().export_ratchet_tree().into()),
                    key_package_bundle,
                    provider,
                    ResumptionPskStore::new(1024),
                ) {
                    Ok(group) => group,
                    Err(err) => panic!("Error creating new group from Welcome: {err:?}"),
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

#[apply(providers)]
fn test_setup(provider: &impl OpenMlsProvider) {
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
    let _test_setup = setup(test_setup_config, provider);
}

#[derive(Clone)]
pub(crate) struct CredentialWithKeyAndSigner {
    pub(crate) credential_with_key: CredentialWithKey,
    pub(crate) signer: SignatureKeyPair,
}

// Helper function to generate a CredentialWithKeyAndSigner
pub(crate) fn generate_credential_with_key(
    identity: Vec<u8>,
    signature_scheme: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> CredentialWithKeyAndSigner {
    let (credential, signer) = {
        let credential = Credential::new(identity, CredentialType::Basic).unwrap();
        let signature_keys = SignatureKeyPair::new(signature_scheme).unwrap();
        signature_keys.store(provider.key_store()).unwrap();

        (credential, signature_keys)
    };
    let signature_key =
        OpenMlsSignaturePublicKey::new(signer.to_public_vec().into(), signature_scheme).unwrap();

    CredentialWithKeyAndSigner {
        credential_with_key: CredentialWithKey {
            credential,
            signature_key: signature_key.into(),
        },
        signer,
    }
}

// Helper function to generate a KeyPackageBundle
pub(crate) fn generate_key_package<KeyStore: OpenMlsKeyStore>(
    ciphersuite: Ciphersuite,
    extensions: Extensions,
    provider: &impl OpenMlsProvider<KeyStoreProvider = KeyStore>,
    credential_with_keys: CredentialWithKeyAndSigner,
) -> KeyPackage {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(
            CryptoConfig {
                ciphersuite,
                version: ProtocolVersion::default(),
            },
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
    provider: &impl OpenMlsProvider,
    signer: &impl Signer,
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

    let membership_key = alice_group.group().message_secrets().membership_key();

    signed_plaintext
        .set_membership_tag(
            provider.crypto(),
            membership_key,
            alice_group.group().message_secrets().serialized_context(),
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
