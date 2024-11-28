use log::{debug, info, warn};
use openmls_traits::{crypto::OpenMlsCrypto, storage::StorageProvider, OpenMlsProvider};
use serde::{self, Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::{
    framing::{MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProcessedMessageContent},
    group::{
        HpkePrivateKey, IncomingWireFormatPolicy, Member, MlsGroup, MlsGroupCreateConfig,
        MlsGroupJoinConfig, OutgoingWireFormatPolicy, StagedWelcome, WireFormatPolicy,
    },
    key_packages::*,
    prelude::LeafNodeParameters,
    schedule::psk::PreSharedKeyId,
    test_utils::*,
    treesync::{
        node::encryption_keys::{EncryptionKeyPair, EncryptionPrivateKey},
        RatchetTreeIn,
    },
};

const TEST_VECTORS_PATH_READ: &[&str] = &[
    "test_vectors/passive-client-welcome.json",
    "test_vectors/passive-client-random.json",
    "test_vectors/passive-client-handling-commit.json",
];
const TEST_VECTOR_PATH_WRITE: &[&str] = &["test_vectors/passive-client-welcome-new.json"];
const NUM_TESTS: usize = 25;

/// ```json
/// {
///   "cipher_suite": /* uint16 */,
///
///   "key_package": /* serialized KeyPackage */,
///   "signature_priv":  /* hex-encoded binary data */,
///   "encryption_priv": /* hex-encoded binary data */,
///   "init_priv": /* hex-encoded binary data */,
///
///   "welcome":  /* serialized MLSMessage (Welcome) */,
///   "initial_epoch_authenticator":  /* hex-encoded binary data */,
///
///   "epochs": [
///     {
///       "proposals": [
///         /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
///         /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
///       ],
///       "commit": /* serialized MLSMessage (PublicMessage or PrivateMessage) */,
///       "epoch_authenticator": /* hex-encoded binary data */,
///     },
///     // ...
///   ]
/// }
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PassiveClientWelcomeTestVector {
    cipher_suite: u16,
    external_psks: Vec<ExternalPskTest>,

    #[serde(with = "hex::serde")]
    key_package: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    init_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    welcome: Vec<u8>,
    ratchet_tree: Option<VecU8>,
    #[serde(with = "hex::serde")]
    initial_epoch_authenticator: Vec<u8>,
    epochs: Vec<TestEpoch>,
}

// Helper to avoid writing a custom deserializer.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct VecU8(#[serde(with = "hex::serde")] Vec<u8>);

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ExternalPskTest {
    #[serde(with = "hex::serde")]
    psk_id: Vec<u8>,
    #[serde(with = "hex::serde")]
    psk: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TestEpoch {
    proposals: Vec<TestProposal>,
    #[serde(with = "hex::serde")]
    commit: Vec<u8>,
    #[serde(with = "hex::serde")]
    epoch_authenticator: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct TestProposal(#[serde(with = "hex::serde")] Vec<u8>);

#[test]
fn test_read_vectors() {
    crate::skip_validation::checks::leaf_node_lifetime::handle().with_disabled(|| {
        for file in TEST_VECTORS_PATH_READ {
            let scenario: Vec<PassiveClientWelcomeTestVector> = read(file);

            info!("# {file}");
            for (i, test_vector) in scenario.into_iter().enumerate() {
                info!("## {i:04} START");
                run_test_vector(test_vector);
                info!("## {i:04} END");
            }
        }
    })
}

pub fn run_test_vector(test_vector: PassiveClientWelcomeTestVector) {
    let _ = pretty_env_logger::try_init();

    let provider = OpenMlsRustCrypto::default();
    let cipher_suite = test_vector.cipher_suite.try_into().unwrap();
    if provider.crypto().supports(cipher_suite).is_err() {
        warn!("Skipping {}", cipher_suite);
        return;
    }

    let group_config = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .number_of_resumption_psks(16)
        .build();

    let mut passive_client = PassiveClient::new(group_config, test_vector.external_psks.clone());

    passive_client.inject_key_package(
        test_vector.key_package,
        test_vector.signature_priv,
        test_vector.encryption_priv,
        test_vector.init_priv,
    );

    let ratchet_tree: Option<RatchetTreeIn> = test_vector
        .ratchet_tree
        .as_ref()
        .map(|bytes| RatchetTreeIn::tls_deserialize_exact(bytes.0.as_slice()).unwrap());

    passive_client.join_by_welcome(
        MlsMessageIn::tls_deserialize_exact(&test_vector.welcome).unwrap(),
        ratchet_tree,
    );

    debug!(
        "Group ID {}",
        bytes_to_hex(passive_client.group.as_ref().unwrap().group_id().as_slice())
    );

    assert_eq!(
        test_vector.initial_epoch_authenticator,
        passive_client.epoch_authenticator()
    );

    for (i, epoch) in test_vector.epochs.into_iter().enumerate() {
        info!("Epoch #{}", i);

        for proposal in epoch.proposals {
            let message = MlsMessageIn::tls_deserialize_exact(&proposal.0).unwrap();
            debug!("Proposal: {message:?}");
            passive_client.process_message(message);
        }

        let message = MlsMessageIn::tls_deserialize_exact(&epoch.commit).unwrap();
        debug!("Commit: {message:#?}");
        passive_client.process_message(message);

        assert_eq!(
            epoch.epoch_authenticator,
            passive_client.epoch_authenticator()
        );
    }
}

#[test]
fn test_write_vectors() {
    crate::skip_validation::checks::leaf_node_lifetime::handle().with_disabled(|| {
        let mut tests = Vec::new();

        for _ in 0..NUM_TESTS {
            for &ciphersuite in OpenMlsRustCrypto::default()
                .crypto()
                .supported_ciphersuites()
                .iter()
            {
                let test = generate_test_vector(ciphersuite);
                tests.push(test);
            }
        }

        // TODO(#1279)
        write(TEST_VECTOR_PATH_WRITE[0], &tests);
    })
}

struct PassiveClient {
    provider: OpenMlsRustCrypto,
    group_config: MlsGroupJoinConfig,
    group: Option<MlsGroup>,
}

impl PassiveClient {
    fn new(group_config: MlsGroupJoinConfig, psks: Vec<ExternalPskTest>) -> Self {
        let provider = OpenMlsRustCrypto::default();

        // Load all PSKs into key store.
        for psk in psks.into_iter() {
            // TODO: Better API?
            // We only construct this to easily save the PSK in the keystore.
            // The nonce is not saved, so it can be empty...
            let psk_id = PreSharedKeyId::external(psk.psk_id, vec![]);
            psk_id.store(&provider, &psk.psk).unwrap();
        }

        Self {
            provider,
            group_config,
            group: None,
        }
    }

    fn inject_key_package(
        &self,
        key_package: Vec<u8>,
        _signature_priv: Vec<u8>,
        encryption_priv: Vec<u8>,
        init_priv: Vec<u8>,
    ) {
        let key_package: KeyPackage = {
            let mls_message_key_package = MlsMessageIn::tls_deserialize_exact(key_package).unwrap();

            match mls_message_key_package.body {
                MlsMessageBodyIn::KeyPackage(key_package) => key_package.into(),
                _ => panic!(),
            }
        };

        let init_priv = HpkePrivateKey::from(init_priv);

        let key_package_bundle = KeyPackageBundle {
            key_package: key_package.clone(),
            private_init_key: init_priv,
            private_encryption_key: encryption_priv.clone().into(),
        };

        // Store key package.
        let hash_ref = key_package.hash_ref(self.provider.crypto()).unwrap();
        self.provider
            .storage()
            .write_key_package(&hash_ref, &key_package_bundle)
            .unwrap();

        // Store encryption key
        let key_pair = EncryptionKeyPair::from((
            key_package.leaf_node().encryption_key().clone(),
            EncryptionPrivateKey::from(encryption_priv),
        ));

        key_pair.write(self.provider.storage()).unwrap();
    }

    fn join_by_welcome(
        &mut self,
        mls_message_welcome: MlsMessageIn,
        ratchet_tree: Option<RatchetTreeIn>,
    ) {
        let welcome = mls_message_welcome
            .into_welcome()
            .expect("expected a welcome");

        let group = StagedWelcome::new_from_welcome(
            &self.provider,
            &self.group_config,
            welcome,
            ratchet_tree,
        )
        .unwrap()
        .into_group(&self.provider)
        .unwrap();

        self.group = Some(group);
    }

    fn process_message(&mut self, message: MlsMessageIn) {
        println!("{:#?}", message);
        let processed_message = self
            .group
            .as_mut()
            .unwrap()
            .process_message(&self.provider, message.into_protocol_message().unwrap())
            .unwrap();

        match processed_message.into_content() {
            ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                self.group
                    .as_mut()
                    .unwrap()
                    .store_pending_proposal(self.provider.storage(), *queued_proposal)
                    .unwrap();
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.group
                    .as_mut()
                    .unwrap()
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .unwrap();
            }
            _ => unimplemented!(),
        }
    }

    fn epoch_authenticator(&self) -> Vec<u8> {
        self.group
            .as_ref()
            .unwrap()
            .epoch_authenticator()
            .as_slice()
            .to_vec()
    }
}

pub fn generate_test_vector(ciphersuite: Ciphersuite) -> PassiveClientWelcomeTestVector {
    let group_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let creator_provider = OpenMlsRustCrypto::default();

    let creator =
        generate_group_candidate(b"Alice (Creator)", ciphersuite, &creator_provider, true);

    let mut creator_group = MlsGroup::new(
        &creator_provider,
        &creator.signature_keypair,
        &group_config,
        creator
            .credential_with_key_and_signer
            .credential_with_key
            .clone(),
    )
    .unwrap();

    let passive = generate_group_candidate(
        b"Bob (Passive Client)",
        ciphersuite,
        &OpenMlsRustCrypto::default(),
        false,
    );

    let (_, mls_message_welcome, _) = creator_group
        .add_members(
            &creator_provider,
            &creator.signature_keypair,
            &[passive.key_package.key_package().clone()],
        )
        .unwrap();

    creator_group
        .merge_pending_commit(&creator_provider)
        .unwrap();

    let initial_epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

    let epoch1 = update_inline(&creator_provider, &creator, &mut creator_group);

    let epoch2 = {
        let proposals = vec![propose_add(
            ciphersuite,
            &creator_provider,
            &creator,
            &mut creator_group,
            b"Charlie",
        )];

        let commit = commit(&creator_provider, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epoch3 = {
        let proposals = vec![propose_remove(
            &creator_provider,
            &creator,
            &mut creator_group,
            b"Charlie",
        )];

        let commit = commit(&creator_provider, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epoch4 = {
        let proposals = vec![
            propose_add(
                ciphersuite,
                &creator_provider,
                &creator,
                &mut creator_group,
                b"Daniel",
            ),
            propose_add(
                ciphersuite,
                &creator_provider,
                &creator,
                &mut creator_group,
                b"Evelin",
            ),
        ];

        let commit = commit(&creator_provider, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epoch5 = {
        let proposals = vec![
            propose_remove(&creator_provider, &creator, &mut creator_group, b"Daniel"),
            propose_add(
                ciphersuite,
                &creator_provider,
                &creator,
                &mut creator_group,
                b"Fardi",
            ),
        ];

        let commit = commit(&creator_provider, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epoch6 = {
        let proposals = vec![
            propose_remove(&creator_provider, &creator, &mut creator_group, b"Fardi"),
            propose_remove(&creator_provider, &creator, &mut creator_group, b"Evelin"),
        ];

        let commit = commit(&creator_provider, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epochs = vec![epoch1, epoch2, epoch3, epoch4, epoch5, epoch6];
    let init_priv = passive.key_package.init_private_key().to_vec();
    let encryption_priv = passive.key_package.encryption_private_key().to_vec();

    PassiveClientWelcomeTestVector {
        cipher_suite: ciphersuite.into(),
        external_psks: vec![],

        key_package: MlsMessageOut::from(passive.key_package)
            .tls_serialize_detached()
            .unwrap(),

        signature_priv: passive.signature_keypair.private().to_vec(),
        encryption_priv,
        init_priv,

        welcome: mls_message_welcome.tls_serialize_detached().unwrap(),
        ratchet_tree: None,
        initial_epoch_authenticator,

        epochs,
    }
}

// -------------------------------------------------------------------------------------------------

fn propose_add(
    cipher_suite: Ciphersuite,
    provider: &OpenMlsRustCrypto,
    candidate: &GroupCandidate,
    group: &mut MlsGroup,
    add_identity: &[u8],
) -> TestProposal {
    let add_candidate = generate_group_candidate(
        add_identity,
        cipher_suite,
        &OpenMlsRustCrypto::default(),
        false,
    );

    let mls_message_out_proposal = group
        .propose_add_member(
            provider,
            &candidate.signature_keypair,
            add_candidate.key_package.key_package(),
        )
        .unwrap();
    group.merge_pending_commit(provider).unwrap();

    TestProposal(mls_message_out_proposal.tls_serialize_detached().unwrap())
}

fn propose_remove(
    provider: &OpenMlsRustCrypto,
    candidate: &GroupCandidate,
    group: &mut MlsGroup,
    remove_identity: &[u8],
) -> TestProposal {
    let remove = group
        .members()
        .find(|Member { credential, .. }| credential.serialized_content() == remove_identity)
        .unwrap()
        .index;

    let mls_message_out_proposal = group
        .propose_remove_member(provider, &candidate.signature_keypair, remove)
        .unwrap();

    TestProposal(mls_message_out_proposal.tls_serialize_detached().unwrap())
}

fn commit(provider: &OpenMlsRustCrypto, creator: &GroupCandidate, group: &mut MlsGroup) -> Vec<u8> {
    let (mls_message_out_commit, _, _) = group
        .commit_to_pending_proposals(provider, &creator.signature_keypair)
        .unwrap();
    group.merge_pending_commit(provider).unwrap();

    mls_message_out_commit.tls_serialize_detached().unwrap()
}

fn update_inline(
    provider: &OpenMlsRustCrypto,
    candidate: &GroupCandidate,
    group: &mut MlsGroup,
) -> TestEpoch {
    let (mls_message_out_commit, _, _) = group
        .self_update(
            provider,
            &candidate.signature_keypair,
            LeafNodeParameters::default(),
        )
        .unwrap()
        .into_contents();
    group.merge_pending_commit(provider).unwrap();

    let proposals = vec![];

    let commit = mls_message_out_commit.tls_serialize_detached().unwrap();

    let epoch_authenticator = group.epoch_authenticator().as_slice().to_vec();

    TestEpoch {
        proposals,
        commit,
        epoch_authenticator,
    }
}
