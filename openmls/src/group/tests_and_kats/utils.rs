//! A framework to create integration tests of the MlsGroup API.
//! # Test utils
//!
//! Most tests require to set up groups, clients, credentials, and identities.
//! This module implements helpers to do that.

use std::{cell::RefCell, collections::HashMap};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{signatures::Signer, types::SignatureScheme};
use rand::Rng;
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
                let processed_welcome =
                    ProcessedWelcome::new_from_welcome(provider, &join_config, welcome.clone())
                        .unwrap();
                let new_group = JoinBuilder::new(provider, processed_welcome)
                    .with_ratchet_tree(mls_group.export_ratchet_tree().into())
                    .replace_old_group()
                    .build()
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
    rand::rng().next_u64() as usize
}

/// No crypto randomness!
pub fn randombytes(n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    rand::rng().fill_bytes(&mut out);
    out
}

#[test]
fn test_random() {
    random_usize();
    randombytes(0);
}

#[openmls_test::openmls_test]
fn test_setup() {
    let provider = &Provider::default();
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
    extensions: Extensions<KeyPackage>,
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

pub(crate) mod storage_error {
    use std::{cell::RefCell, collections::HashMap};

    use openmls_rust_crypto::RustCrypto;
    use openmls_traits::{storage::CURRENT_VERSION, OpenMlsProvider};

    // Customizable provider for use in tests
    pub(crate) struct TestProvider<S>
    where
        S: openmls_traits::storage::StorageProvider<CURRENT_VERSION>,
    {
        pub(crate) storage: S,
        pub(crate) crypto_rand: RustCrypto,
    }

    impl<S> OpenMlsProvider for TestProvider<S>
    where
        S: openmls_traits::storage::StorageProvider<CURRENT_VERSION>,
    {
        type CryptoProvider = RustCrypto;
        type RandProvider = RustCrypto;
        type StorageProvider = S;

        fn storage(&self) -> &Self::StorageProvider {
            &self.storage
        }

        fn crypto(&self) -> &Self::CryptoProvider {
            &self.crypto_rand
        }

        fn rand(&self) -> &Self::RandProvider {
            &self.crypto_rand
        }
    }

    // Storage provider for use in tests, can be configured to return custom errors on method calls.
    pub(crate) struct TestStorageProvider<
        'a,
        D: openmls_traits::storage::StorageProvider<CURRENT_VERSION>,
    > {
        pub(crate) delegate: &'a D,

        /// Maps method names to reverse sequence of errors to return
        /// If a method name is not included, delegates to [`Self::delegate`].
        pub(crate) errors: RefCell<
            HashMap<
                &'static str,
                Vec<<Self as openmls_traits::storage::StorageProvider<CURRENT_VERSION>>::Error>,
            >,
        >,
    }

    // Custom errors that can wrap the errors of the inner provider or custom strings
    #[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
    pub(crate) enum TestStorageError<D>
    where
        D: core::fmt::Debug + std::error::Error,
    {
        #[error("Error '{0}' was injected for testing.")]
        Injected(&'static str),
        #[error("An error occurred during delegation: {0}")]
        Delegated(D),
    }

    impl<'a, D: openmls_traits::storage::StorageProvider<CURRENT_VERSION>> TestStorageProvider<'a, D> {
        fn try_error(&self, function_name: &str) -> Result<(), TestStorageError<D::Error>> {
            match self.errors.borrow_mut().get_mut(function_name) {
                None => Ok(()),
                Some(vec) => match vec.pop() {
                    None => Ok(()),
                    Some(error) => Err(error),
                },
            }
        }

        fn wrap_result<T>(
            &self,
            result: Result<T, D::Error>,
        ) -> Result<T, <Self as openmls_traits::storage::StorageProvider<CURRENT_VERSION>>::Error>
        {
            result.map_err(TestStorageError::Delegated)
        }
    }

    impl<'a, D> openmls_traits::storage::StorageProvider<CURRENT_VERSION> for TestStorageProvider<'a, D>
    where
        D: openmls_traits::storage::StorageProvider<CURRENT_VERSION>,
    {
        type Error = TestStorageError<D::Error>;

        fn write_mls_join_config<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            config: &MlsGroupJoinConfig,
        ) -> Result<(), Self::Error> {
            self.try_error("write_mls_join_config")?;
            self.wrap_result(self.delegate.write_mls_join_config(group_id, config))
        }

        fn append_own_leaf_node<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            LeafNode: openmls_traits::storage::traits::LeafNode<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            leaf_node: &LeafNode,
        ) -> Result<(), Self::Error> {
            self.try_error("append_own_leaf_node")?;
            self.wrap_result(self.delegate.append_own_leaf_node(group_id, leaf_node))
        }

        fn queue_proposal<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
            QueuedProposal: openmls_traits::storage::traits::QueuedProposal<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            proposal_ref: &ProposalRef,
            proposal: &QueuedProposal,
        ) -> Result<(), Self::Error> {
            self.try_error("queue_proposal")?;
            self.wrap_result(
                self.delegate
                    .queue_proposal(group_id, proposal_ref, proposal),
            )
        }

        fn write_tree<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            TreeSync: openmls_traits::storage::traits::TreeSync<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            tree: &TreeSync,
        ) -> Result<(), Self::Error> {
            self.try_error("write_tree")?;
            self.wrap_result(self.delegate.write_tree(group_id, tree))
        }

        fn write_interim_transcript_hash<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            interim_transcript_hash: &InterimTranscriptHash,
        ) -> Result<(), Self::Error> {
            self.try_error("write_interim_transcript_hash")?;
            self.wrap_result(
                self.delegate
                    .write_interim_transcript_hash(group_id, interim_transcript_hash),
            )
        }

        fn write_context<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            GroupContext: openmls_traits::storage::traits::GroupContext<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_context: &GroupContext,
        ) -> Result<(), Self::Error> {
            self.try_error("write_context")?;
            self.wrap_result(self.delegate.write_context(group_id, group_context))
        }

        fn write_confirmation_tag<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            confirmation_tag: &ConfirmationTag,
        ) -> Result<(), Self::Error> {
            self.try_error("write_confirmation_tag")?;
            self.wrap_result(
                self.delegate
                    .write_confirmation_tag(group_id, confirmation_tag),
            )
        }

        fn write_group_state<
            GroupState: openmls_traits::storage::traits::GroupState<CURRENT_VERSION>,
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_state: &GroupState,
        ) -> Result<(), Self::Error> {
            self.try_error("write_group_state")?;
            self.wrap_result(self.delegate.write_group_state(group_id, group_state))
        }

        fn write_message_secrets<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            MessageSecrets: openmls_traits::storage::traits::MessageSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            message_secrets: &MessageSecrets,
        ) -> Result<(), Self::Error> {
            self.try_error("write_message_secrets")?;
            self.wrap_result(
                self.delegate
                    .write_message_secrets(group_id, message_secrets),
            )
        }

        fn write_resumption_psk_store<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            resumption_psk_store: &ResumptionPskStore,
        ) -> Result<(), Self::Error> {
            self.try_error("write_resumption_psk_store")?;
            self.wrap_result(
                self.delegate
                    .write_resumption_psk_store(group_id, resumption_psk_store),
            )
        }

        fn write_own_leaf_index<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            own_leaf_index: &LeafNodeIndex,
        ) -> Result<(), Self::Error> {
            self.try_error("write_own_leaf_index")?;
            self.wrap_result(self.delegate.write_own_leaf_index(group_id, own_leaf_index))
        }

        fn write_group_epoch_secrets<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_epoch_secrets: &GroupEpochSecrets,
        ) -> Result<(), Self::Error> {
            self.try_error("write_group_epoch_secrets")?;
            self.wrap_result(
                self.delegate
                    .write_group_epoch_secrets(group_id, group_epoch_secrets),
            )
        }

        fn write_signature_key_pair<
            SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
            SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
            signature_key_pair: &SignatureKeyPair,
        ) -> Result<(), Self::Error> {
            self.try_error("write_signature_key_pair")?;
            self.wrap_result(
                self.delegate
                    .write_signature_key_pair(public_key, signature_key_pair),
            )
        }

        fn write_encryption_key_pair<
            EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
            HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &EncryptionKey,
            key_pair: &HpkeKeyPair,
        ) -> Result<(), Self::Error> {
            self.try_error("write_encryption_key_pair")?;
            self.wrap_result(
                self.delegate
                    .write_encryption_key_pair(public_key, key_pair),
            )
        }

        fn write_encryption_epoch_key_pairs<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
            HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
            key_pairs: &[HpkeKeyPair],
        ) -> Result<(), Self::Error> {
            self.try_error("write_encryption_epoch_key_pairs")?;
            self.wrap_result(
                self.delegate
                    .write_encryption_epoch_key_pairs(group_id, epoch, leaf_index, key_pairs),
            )
        }

        fn write_key_package<
            HashReference: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
            KeyPackage: openmls_traits::storage::traits::KeyPackage<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &HashReference,
            key_package: &KeyPackage,
        ) -> Result<(), Self::Error> {
            self.try_error("write_key_package")?;
            self.wrap_result(self.delegate.write_key_package(hash_ref, key_package))
        }

        fn write_psk<
            PskId: openmls_traits::storage::traits::PskId<CURRENT_VERSION>,
            PskBundle: openmls_traits::storage::traits::PskBundle<CURRENT_VERSION>,
        >(
            &self,
            psk_id: &PskId,
            psk: &PskBundle,
        ) -> Result<(), Self::Error> {
            self.try_error("write_psk")?;
            self.wrap_result(self.delegate.write_psk(psk_id, psk))
        }

        fn mls_group_join_config<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            MlsGroupJoinConfig: openmls_traits::storage::traits::MlsGroupJoinConfig<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
            self.try_error("mls_group_join_config")?;
            self.wrap_result(self.delegate.mls_group_join_config(group_id))
        }

        fn own_leaf_nodes<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            LeafNode: openmls_traits::storage::traits::LeafNode<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<LeafNode>, Self::Error> {
            self.try_error("own_leaf_nodes")?;
            self.wrap_result(self.delegate.own_leaf_nodes(group_id))
        }

        fn queued_proposal_refs<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<ProposalRef>, Self::Error> {
            self.try_error("queued_proposal_refs")?;
            self.wrap_result(self.delegate.queued_proposal_refs(group_id))
        }

        fn queued_proposals<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
            QueuedProposal: openmls_traits::storage::traits::QueuedProposal<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
            self.try_error("queued_proposals")?;
            self.wrap_result(self.delegate.queued_proposals(group_id))
        }

        fn tree<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            TreeSync: openmls_traits::storage::traits::TreeSync<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<TreeSync>, Self::Error> {
            self.try_error("tree")?;
            self.wrap_result(self.delegate.tree(group_id))
        }

        fn group_context<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            GroupContext: openmls_traits::storage::traits::GroupContext<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupContext>, Self::Error> {
            self.try_error("group_context")?;
            self.wrap_result(self.delegate.group_context(group_id))
        }

        fn interim_transcript_hash<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            InterimTranscriptHash: openmls_traits::storage::traits::InterimTranscriptHash<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
            self.try_error("interim_transcript_hash")?;
            self.wrap_result(self.delegate.interim_transcript_hash(group_id))
        }

        fn confirmation_tag<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ConfirmationTag: openmls_traits::storage::traits::ConfirmationTag<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ConfirmationTag>, Self::Error> {
            self.try_error("confirmation_tag")?;
            self.wrap_result(self.delegate.confirmation_tag(group_id))
        }

        fn group_state<
            GroupState: openmls_traits::storage::traits::GroupState<CURRENT_VERSION>,
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupState>, Self::Error> {
            self.try_error("group_state")?;
            self.wrap_result(self.delegate.group_state(group_id))
        }

        fn message_secrets<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            MessageSecrets: openmls_traits::storage::traits::MessageSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<MessageSecrets>, Self::Error> {
            self.try_error("message_secrets")?;
            self.wrap_result(self.delegate.message_secrets(group_id))
        }

        fn resumption_psk_store<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ResumptionPskStore: openmls_traits::storage::traits::ResumptionPskStore<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ResumptionPskStore>, Self::Error> {
            self.try_error("resumption_psk_store")?;
            self.wrap_result(self.delegate.resumption_psk_store(group_id))
        }

        fn own_leaf_index<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            LeafNodeIndex: openmls_traits::storage::traits::LeafNodeIndex<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<LeafNodeIndex>, Self::Error> {
            self.try_error("own_leaf_index")?;
            self.wrap_result(self.delegate.own_leaf_index(group_id))
        }

        fn group_epoch_secrets<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            GroupEpochSecrets: openmls_traits::storage::traits::GroupEpochSecrets<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
            self.try_error("group_epoch_secrets")?;
            self.wrap_result(self.delegate.group_epoch_secrets(group_id))
        }

        fn signature_key_pair<
            SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
            SignatureKeyPair: openmls_traits::storage::traits::SignatureKeyPair<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
        ) -> Result<Option<SignatureKeyPair>, Self::Error> {
            self.try_error("signature_key_pair")?;
            self.wrap_result(self.delegate.signature_key_pair(public_key))
        }

        fn encryption_key_pair<
            HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
            EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
        >(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<Option<HpkeKeyPair>, Self::Error> {
            self.try_error("encryption_key_pair")?;
            self.wrap_result(self.delegate.encryption_key_pair(public_key))
        }

        fn encryption_epoch_key_pairs<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
            HpkeKeyPair: openmls_traits::storage::traits::HpkeKeyPair<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
        ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
            self.try_error("encryption_epoch_key_pairs")?;
            self.wrap_result(
                self.delegate
                    .encryption_epoch_key_pairs(group_id, epoch, leaf_index),
            )
        }

        fn key_package<
            KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
            KeyPackage: openmls_traits::storage::traits::KeyPackage<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<Option<KeyPackage>, Self::Error> {
            self.try_error("key_package")?;
            self.wrap_result(self.delegate.key_package(hash_ref))
        }

        fn psk<
            PskBundle: openmls_traits::storage::traits::PskBundle<CURRENT_VERSION>,
            PskId: openmls_traits::storage::traits::PskId<CURRENT_VERSION>,
        >(
            &self,
            psk_id: &PskId,
        ) -> Result<Option<PskBundle>, Self::Error> {
            self.try_error("psk")?;
            self.wrap_result(self.delegate.psk(psk_id))
        }

        fn remove_proposal<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            proposal_ref: &ProposalRef,
        ) -> Result<(), Self::Error> {
            self.try_error("remove_proposal")?;
            self.wrap_result(self.delegate.remove_proposal(group_id, proposal_ref))
        }

        fn delete_own_leaf_nodes<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_own_leaf_nodes")?;
            self.wrap_result(self.delegate.delete_own_leaf_nodes(group_id))
        }

        fn delete_group_config<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_group_config")?;
            self.wrap_result(self.delegate.delete_group_config(group_id))
        }

        fn delete_tree<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_tree")?;
            self.wrap_result(self.delegate.delete_tree(group_id))
        }

        fn delete_confirmation_tag<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_confirmation_tag")?;
            self.wrap_result(self.delegate.delete_confirmation_tag(group_id))
        }

        fn delete_group_state<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_group_state")?;
            self.wrap_result(self.delegate.delete_group_state(group_id))
        }

        fn delete_context<GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>>(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_context")?;
            self.wrap_result(self.delegate.delete_context(group_id))
        }

        fn delete_interim_transcript_hash<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_interim_transcript_hash")?;
            self.wrap_result(self.delegate.delete_interim_transcript_hash(group_id))
        }

        fn delete_message_secrets<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_message_secrets")?;
            self.wrap_result(self.delegate.delete_message_secrets(group_id))
        }

        fn delete_all_resumption_psk_secrets<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_all_resumption_psk_secrets")?;
            self.wrap_result(self.delegate.delete_all_resumption_psk_secrets(group_id))
        }

        fn delete_own_leaf_index<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_own_leaf_index")?;
            self.wrap_result(self.delegate.delete_own_leaf_index(group_id))
        }

        fn delete_group_epoch_secrets<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_group_epoch_secrets")?;
            self.wrap_result(self.delegate.delete_group_epoch_secrets(group_id))
        }

        fn clear_proposal_queue<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ProposalRef: openmls_traits::storage::traits::ProposalRef<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("clear_proposal_queue")?;
            self.wrap_result(
                self.delegate
                    .clear_proposal_queue::<GroupId, ProposalRef>(group_id),
            )
        }

        fn delete_signature_key_pair<
            SignaturePublicKey: openmls_traits::storage::traits::SignaturePublicKey<CURRENT_VERSION>,
        >(
            &self,
            public_key: &SignaturePublicKey,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_signature_key_pair")?;
            self.wrap_result(self.delegate.delete_signature_key_pair(public_key))
        }

        fn delete_encryption_key_pair<
            EncryptionKey: openmls_traits::storage::traits::EncryptionKey<CURRENT_VERSION>,
        >(
            &self,
            public_key: &EncryptionKey,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_encryption_key_pair")?;
            self.wrap_result(self.delegate.delete_encryption_key_pair(public_key))
        }

        fn delete_encryption_epoch_key_pairs<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch: &EpochKey,
            leaf_index: u32,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_encryption_epoch_key_pairs")?;
            self.wrap_result(
                self.delegate
                    .delete_encryption_epoch_key_pairs(group_id, epoch, leaf_index),
            )
        }

        fn delete_key_package<
            KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_key_package")?;
            self.wrap_result(self.delegate.delete_key_package(hash_ref))
        }

        fn delete_psk<PskKey: openmls_traits::storage::traits::PskId<CURRENT_VERSION>>(
            &self,
            psk_id: &PskKey,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_psk")?;
            self.wrap_result(self.delegate.delete_psk(psk_id))
        }

        #[cfg(feature = "extensions-draft")]
        fn write_application_export_tree<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ApplicationExportTree: openmls_traits::storage::traits::ApplicationExportTree<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            application_export_tree: &ApplicationExportTree,
        ) -> Result<(), Self::Error> {
            self.try_error("write_application_export_tree")?;
            self.wrap_result(
                self.delegate
                    .write_application_export_tree(group_id, application_export_tree),
            )
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_derivation_epoch_state<
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
            VcDerivationEpochState: openmls_traits::storage::traits::VcDerivationEpochState<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
            vc_derivation_epoch_state: &VcDerivationEpochState,
        ) -> Result<(), Self::Error> {
            self.try_error("write_vc_derivation_epoch_state")?;
            self.wrap_result(
                self.delegate
                    .write_vc_derivation_epoch_state(epoch_id, vc_derivation_epoch_state),
            )
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_operation_tree<
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
            VcOperationTree: openmls_traits::storage::traits::VcOperationTree<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
            vc_operation_tree: &VcOperationTree,
        ) -> Result<(), Self::Error> {
            self.try_error("write_vc_operation_tree")?;
            self.wrap_result(
                self.delegate
                    .write_vc_operation_tree(epoch_id, vc_operation_tree),
            )
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_retained_key_package_material_batch<
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
            VcOperationTree: openmls_traits::storage::traits::VcOperationTree<CURRENT_VERSION>,
            KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
            RetainedKeyPackageMaterial: openmls_traits::storage::traits::RetainedKeyPackageMaterial<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
            operation_tree: &VcOperationTree,
            materials: &[(KeyPackageRef, RetainedKeyPackageMaterial)],
        ) -> Result<(), Self::Error> {
            self.try_error("write_retained_key_package_material_batch")?;
            self.wrap_result(self.delegate.write_retained_key_package_material_batch(
                epoch_id,
                operation_tree,
                materials,
            ))
        }

        #[cfg(feature = "extensions-draft")]
        fn application_export_tree<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ApplicationExportTree: openmls_traits::storage::traits::ApplicationExportTree<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Option<ApplicationExportTree>, Self::Error> {
            self.try_error("application_export_tree")?;
            self.wrap_result(self.delegate.application_export_tree(group_id))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn vc_derivation_epoch_state<
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
            VcDerivationEpochState: openmls_traits::storage::traits::VcDerivationEpochState<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
        ) -> Result<Option<VcDerivationEpochState>, Self::Error> {
            self.try_error("vc_derivation_epoch_state")?;
            self.wrap_result(self.delegate.vc_derivation_epoch_state(epoch_id))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn vc_operation_tree<
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
            VcOperationTree: openmls_traits::storage::traits::VcOperationTree<CURRENT_VERSION>,
        >(
            &self,
            epoch_id: &EpochId,
        ) -> Result<Option<VcOperationTree>, Self::Error> {
            self.try_error("vc_operation_tree")?;
            self.wrap_result(self.delegate.vc_operation_tree(epoch_id))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn retained_key_package_material<
            KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
            RetainedKeyPackageMaterial: openmls_traits::storage::traits::RetainedKeyPackageMaterial<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<Option<RetainedKeyPackageMaterial>, Self::Error> {
            self.try_error("retained_key_package_material")?;
            self.wrap_result(self.delegate.retained_key_package_material(hash_ref))
        }

        #[cfg(feature = "extensions-draft")]
        fn delete_application_export_tree<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            ApplicationExportTree: openmls_traits::storage::traits::ApplicationExportTree<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_application_export_tree")?;
            self.wrap_result(
                self.delegate
                    .delete_application_export_tree::<GroupId, ApplicationExportTree>(group_id),
            )
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_emulation_binding<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
            VcEmulationBinding: openmls_traits::storage::traits::VcEmulationBinding<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_epoch: &EpochKey,
            epoch_id: &EpochId,
            binding: &VcEmulationBinding,
        ) -> Result<(), Self::Error> {
            self.try_error("write_vc_emulation_binding")?;
            self.wrap_result(self.delegate.write_vc_emulation_binding(
                group_id,
                group_epoch,
                epoch_id,
                binding,
            ))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn write_vc_derivation_epoch_log_entry<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
            VcDerivationEpochLogEntry: openmls_traits::storage::traits::VcDerivationEpochLogEntry<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch_id: &EpochId,
            entry: &VcDerivationEpochLogEntry,
        ) -> Result<(), Self::Error> {
            self.try_error("write_vc_derivation_epoch_log_entry")?;
            self.wrap_result(
                self.delegate
                    .write_vc_derivation_epoch_log_entry(group_id, epoch_id, entry),
            )
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn vc_emulation_binding<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
            VcEmulationBinding: openmls_traits::storage::traits::VcEmulationBinding<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_epoch: &EpochKey,
        ) -> Result<Option<VcEmulationBinding>, Self::Error> {
            self.try_error("vc_emulation_binding")?;
            self.wrap_result(self.delegate.vc_emulation_binding(group_id, group_epoch))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn vc_emulation_bindings<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            VcEmulationBinding: openmls_traits::storage::traits::VcEmulationBinding<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<VcEmulationBinding>, Self::Error> {
            self.try_error("vc_emulation_bindings")?;
            self.wrap_result(self.delegate.vc_emulation_bindings(group_id))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn vc_derivation_epoch_log_entries<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            VcDerivationEpochLogEntry: openmls_traits::storage::traits::VcDerivationEpochLogEntry<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<Vec<VcDerivationEpochLogEntry>, Self::Error> {
            self.try_error("vc_derivation_epoch_log_entries")?;
            self.wrap_result(self.delegate.vc_derivation_epoch_log_entries(group_id))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_unreferenced_vc_derivation_epoch_states<
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        >(
            &self,
        ) -> Result<Vec<EpochId>, Self::Error> {
            self.try_error("delete_unreferenced_vc_derivation_epoch_states")?;
            self.wrap_result(
                self.delegate
                    .delete_unreferenced_vc_derivation_epoch_states(),
            )
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_vc_emulation_bindings<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            EpochKey: openmls_traits::storage::traits::EpochKey<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            group_epochs: &[EpochKey],
        ) -> Result<(), Self::Error> {
            self.try_error("delete_vc_emulation_bindings")?;
            self.wrap_result(
                self.delegate
                    .delete_vc_emulation_bindings(group_id, group_epochs),
            )
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_all_vc_emulation_bindings<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_all_vc_emulation_bindings")?;
            self.wrap_result(self.delegate.delete_all_vc_emulation_bindings(group_id))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_vc_derivation_epoch_log_entries<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
            EpochId: openmls_traits::storage::traits::VcEpochId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
            epoch_ids: &[EpochId],
        ) -> Result<(), Self::Error> {
            self.try_error("delete_vc_derivation_epoch_log_entries")?;
            self.wrap_result(
                self.delegate
                    .delete_vc_derivation_epoch_log_entries(group_id, epoch_ids),
            )
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_vc_derivation_epoch_log<
            GroupId: openmls_traits::storage::traits::GroupId<CURRENT_VERSION>,
        >(
            &self,
            group_id: &GroupId,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_vc_derivation_epoch_log")?;
            self.wrap_result(self.delegate.delete_vc_derivation_epoch_log(group_id))
        }

        #[cfg(feature = "virtual-clients-draft")]
        fn delete_retained_key_package_material<
            KeyPackageRef: openmls_traits::storage::traits::HashReference<CURRENT_VERSION>,
        >(
            &self,
            hash_ref: &KeyPackageRef,
        ) -> Result<(), Self::Error> {
            self.try_error("delete_retained_key_package_material")?;
            self.wrap_result(self.delegate.delete_retained_key_package_material(hash_ref))
        }
    }
}
