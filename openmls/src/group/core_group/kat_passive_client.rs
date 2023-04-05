use log::{debug, info, warn};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, key_store::OpenMlsKeyStore, OpenMlsCryptoProvider};
use serde::{self, Deserialize, Serialize};
use tls_codec::Serialize as TlsSerialize;

use crate::{
    framing::{
        MlsMessageIn, MlsMessageInBody, MlsMessageOut, ProcessedMessageContent, TlsFromBytes,
    },
    group::{config::CryptoConfig, *},
    key_packages::*,
    prelude::{ProcessMessageError, ProposalValidationError, StageCommitError},
    schedule::{errors::PskError, psk::PreSharedKeyId},
    test_utils::*,
    treesync::{
        node::encryption_keys::{EncryptionKeyPair, EncryptionPrivateKey},
        RatchetTree,
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
///
/// ```json
///     "cipher_suite": 1,
///     "external_psks": [],
///     "key_package": "00010005000100012027eda0a6943bdaf78e8421903d921dff2833738853ff5ff7231839f81f62f05720afc80b9994962bda4bc1cfe02260a5b48a962e6fb78ef0848996a7dc7691746b202756a27055efed67e3b1e96910cd2be258fadde795c754c2253fc76fb5336e3300010641726e6f6c640200010e0001000200030004000500060007000002000101000000006401d67f0000000065e309ff004040986997da7096e69ba28a89d48738eb30bb173af40768c0bd5233889ef1ac429e6e00030e892d939719e0340c89d4eda0cb3d6a0a91330670e6841889708c050b0040406ecfea01c93873beb6695f010c40cb135e37ed5b2758a4f8c517ca4c03d6c12d32c48e50844797e1d28addaea3849b64ada646b080547fcabadf1e910a58f507",
///     "signature_priv": "08c760e174e466ec33ff13eb72eadd44e1b7842bc5b25cfe1ebe755733f7b26c",
///     "encryption_priv": "e8efc1bf8bb3c1b9e5f2d87968ce992eadb35cef7e1873ba1c8a0871a7acb144",
///     "init_priv": "508db80759585286d5aed532221beb5a168a62f8ef443841bb41e00358680250",
///     "welcome": "0001000300014098201bda58217db244a67863b9cee6eb8fc1b6927bccbaf283504e0385ad6f0e4f5920c64baaa668c3b0e2a0d99bc01fa11c5e641e7908ba0f92a49ea921b245deba1a4054f63c8a75ebd5baa4713ea1e72547ba3440fe183647f0ce971f72a84b1ad79826d6b6fb43a19dd78873d8c8bc93fb6dde8d25645c72260cf29c0b5b2a360e13781fe41ead9654e4382900e94452bace8afaf818f34d4cbddc70092f1b676776bfcbf6e0df460df519107ccbcfe70980139d9c1dc13324fb3886acd19ed39bdf166a66dad98fe5511f7edc70c44f800571c532f0c7d6d9684a2bec59e6a42e8ffb1e4c703c4f3098d577f6210f339117e1a435ee848ce303b94ce7ab236f99a287349968d3905c1d100430c70021b8bab1b436f14dff867afa6db82d058dafb3dcf929bb414d0e8cf2f1ec0619c1769a5b9c5b4b29b63b07ff0dd326f60c2f41aa0c7ac091a870e85f104b186d511ff3997cf03dc501b493606976859916aebdc0ac708f0b50793b426449944ac1f49766af815d33bf3b07a3c567312893c8cc2dd02091ca8fc1f3e600fd6c8f6370f78f714f295c83aefbbc2e9de4a3620d42599d466773bf0d5c3cf2eead051d4b3a90bdf13d8cb81674c47a646d1861eba172b50bdd3b1a408831625c1197e627cd869eea08dbd9b38c860e6b0183aa3139c826b13a1dea21f7ba7b7398fd9d0862ce1c97c01f7124cd0e9f4f19983d4f645a4fc91616c40b808df57c5a81f841e96c034ca7ee7016f40a3b893f97f2a5740d18d0e56c51caf4a1cf8e9e6425ae1a95e8cfec85b3e3a2299b10a35d061e5b017496247b8cb30f2e06144904c31e28266ffabe2bd632b099968e94b15c67cffbd6e12bdbced4542fd5a8c150ff7ecb3b5f5e87d2fa7a08e189e616fd5c012f4f3eb2aa93f468096de974bf0f5c820c6f240e5b1bb464e875bf6cb3ef88a6db26999c94934e8ba29c3c4d628a3e1d7aa907b964e523132c1ed55faef5909ff4afc38cf63507884ad4e4566f493c72bdf58d072ad7124d56c78e2e492dff6d59e34a1ebb1e786254724dd72cd06721ecf5a3435cb5824080ddb462226d579c6a0edfd237561650c106390ad946efa3f45a42ed1f0c5c97160847419db85fe92b22c58fe35d8f968113ffb51a3b5a04e4a24b746d626cc8a374bc4b3f5bcffd3cdd9f7cd44cbc7ed64eebb1941f2fc4d82afa3bb142919a1c3c74931cf2321374494139842ad1eb7a63633ff15b18c851ea1ee775bb577d4299407a44c738a741ca25fc6c0ed4b66f5b5d42077b5f77cbf2bf90937802eed335f651d3beebbde2f16f441392b04829d4f3a663d6aa6e101fc32cbee2374db41317cf8803ff4ece7121f04f8999ce5d6b35910e71d64c2f5829dab471f5c669f4310df38418cc6badb2fc8ac480e149cd94be63c71d3539b1e62959dbc8f2f8a005ad70aeae8b4f447a73e47bb35d35acfdaab01a62d64a83a1ed469729b226e422984296860cff0db237c045790120f43b3cd3a1ad36ea670239acfd32030a84628e08f7eb1e6c6f7b782a160f6a0150fa91d6ab138a562e05033dd1e8b68402d3f95bdbbaa9fdd1c5f1f823a2f6d6422cc0ae8b56a1aa743876fe017a79c8827dea79830f44452fb3dd44bc35c8dfe5a778d083ad8c1bb0a44b6fb03fc38bfebe5080eee7ed428b078eb9c55b4318354af7d6641d7923b75e86a4a978b035eb8e4c850799ef891fa197c9f863609cfd0db7b5d40ec2d10827a13b2d6ba8925e4a9444ffa3ad6352f1bafbf59937dd7acb3c8d6d897d366b65534200256abb9c56fce7421b368580b63f8295b32a5c582e2f16059e0f215675eb34172bca2d3a1b012a0ac9cb9f498e7035fa1d497f9768f00f2722356ae106368b367ad0954bf5bdda4c704b015430791e553a5f8090bea49c3ae4efa5c3235680720091618ffc4afb54818c00b5df64f8bafe2d25f27883a0490065a009c79e1763fbddf0d9d18c891cf6075e0b496bddff5952fe82088d316751bd6748310b6e3de8897be06b99a2ed8dc335e6dd15de3a9936a9a609af728965a584051b74a5df7dfa1385dcda9e0fc4b336094aa50a8dd7158d04467cd859ff5d474f698abd4f25f7e8354fb171c801d9cb27610760020124ddb084023f1a2136637dddea94a60cd66c2a4a917444eab7689a3a9c59bcb53246069b225e764ab5ed54d26c42e1a22b99ecda91198d8fb0117ba9277f98ccc5ee7cdbeb729a9767f53a51303637cc5e1683bfb8a52afb4ad03b377764e5b22609674f2fbc6a61d28ac56d42370afc587997f859c443f74a04cfde3dff7d3a15777892e6c59124f405c0d30a62e11f985caacdea13cf52dc4cf26a776e45708f92309fd74a21d33505a772d5dd1a9dd4b54ef7b87fd1399935abc66c5be2fe23be14cb452e51dd4a9abe2beb908b884762bd06ef5af73567d87ddca0f31358a614dcbc2d66f3b4bc8e0ca514fcd569adcb7ae02e3a56affb88344ba5f452d37019192fc6ec9e43ceeef41d492dc101017d9fc5b000d7240b9742c2b51b636870887f1a5aa1201e14385fefb07a92345fc08c4400d08a1c79b6503000cd8f556f71be8655e94706acad90105a5109f3f3984e46d7c1daca2f43a99bc3dd817e189576310bacd9645d3fa0fc4540610f584fc3a1cb8aeeab3812d7ceddcb684242672d5e9d538c116611d90717462347b4a22b78d7d2fb127ac8875fa4135c8673c7185f2a96cf9097613bfd9696a15bdb2f49a17e4f6c0d5e69fa37eba4729c4a5704047bc67011fd58ffd553211704bc4f428b0eec14671777e4a569d81be944f072824b1384637c6ebda14691a02ba2c8fa57d7adc694f1be91e39f7c459713ab167d383b2636a464d220c9a683c56ba043d0e29abb87f0e61f9e2a1fa9b4ff4ce386b55197decd93a571078213e0623f24f6010f3df255c8ef1ccc05f2dfab20bad9786ccba30c3e5b59fe5060bd7b7bf3ce32eca2d0317bab34e4f553c3766309fe7c014c5a164b080b1f4732fba8eb2fb5f41aa50b88edd70db8466c169bdd27681f7b68f76f0987d27f0aad320bdaf0ff37dda0b839df3665e8be954fa1466ec815d87d66c869e643332bc49c0062215d818e89f36eef102df5340f86e618f70ca0665254ec4005d5815b6c1da6a96536ac11fa7aa94b2fdec795c9c29e34aea29f600f3a5653dbc56fc268fd0df5e912bc1a2dfeb1ac989d10ce9c55d34567a802e0ca8b962c9111bef4b78a313a124fef03085438ba8a1521e83cfdbd293fb67230abd6293ef763997e23dc5b5a9374647aaffa5e2a14e49f5a0f19ee24fc59f3dad1956b491cf9f75f30567775feb310658512933602c1d8cf4a902f7573c2e77338982eb61fed2bf4081458503602496ec4aa883fa2c010f82e3727bd95e2be72eda849d51715e95049ffb84d129cea118bd21283b090e8d3f8d212f9f10f63679b1c6c71fd20712573d4f22ab230b3219405def9aab481661b3f050649c0402e921f533346145f4cd232baff2d92d06e4dd51efae812c47d557a29f82b149d9348a67db66005d18e10f4915adfe852fa6ebc2b3cdc761dcc0627193512984223f252f6155671e77857bdce0730322b5b0ca499088e2a9ae25a80daba9f989a830b09bd645cca9ebc4e2df3a52a193a0c2f7e8f5f931f8211ad291c0aa7e094393cb8baf9d7b8cd67087e9000632c0ce8ceab65a64c41e835f3ea9c338468b09509976bdf092a977f7916b56f634a39391af382439c00f356cbd9fe19d68287828153126f282e67c9c39078f83190b0ce861a1d3e7688d201917057d41c2e10e3cf955cc5111223273a18d896d25d5237fe25760a1cc0d942c64aa26c308645b0d6273598d5d718c80211ea7a84393808128371124e84b4834da5dc032a66a662002c9f11b8e634df203f5b4d298e2655518cd866b2e7b13ff02dbe684b71698f69c60351cb34e93516185b192463be721aea429cce2d84fdbf4b9eab90ca20bc00b886cce25003cba984b8c23f065b3a3fa1f5dda474eedd15b1e634289ba6a23331c69167b4f6d49a65f679785b857c62953bb1bb42b0b66c02a13e19f574d0ba91eb5ccc2cfd5c4b83c6ac587dc63e2a4de39a768d36221512f7e3d98b877a173f1ff510445a3f782860651e5d5e17cc312f4f6bdb5a6cc3e4c13a075b262dfe2cfc415b1496c534b7396a4c2c4f386d295781c3f70e3e790d84af4537128da3d81137f1eac9ffc56e10ccdba8e96fd5c9ddc60869cf7f6ed64b32ad3b4d8263339bfd93b0b65d1a59cc0bc161089c87924bc7e328d30ad4bedb44b3a811bfa9163749f20cdbf1f48e8be3874a59fabc9bbd72dd3481c724ca72aa033685395de6fa26012e067ba7d11df3545681403f9793f80dc5958c9599dd62dd1cfb8c4101212fbb70ca1848deaaf767b3b3657fd1341b2f00dbe52b8679917ea2fbcd6bf6893d472bd8c41f8958dc07226e3848b824811c26ef83697b7dca8e8ecf14ea77945fec480f956632e0a7e18e07f1a70c076f6bcc2870e7617151668ab8ff8324614e2fb90efba8787840fe49f6cd6e12fd620e269ae524bc042f2f7843d707296583f9849430f44e83c78b0c34d38f237e40720d89ac4bc230d2265c52658f1c109272b2ac0d2170fa7bca1152ca3062f3eb5328be6b9db132cc2e697b88525f6754cbe81ca8ab4366ef60b35a18b8b646c6ad675033a299ad70b5da8d913580203910d98d7d28f9a1c6583daca032de706a90737dcdede7606dfb0dcc33463e5153e0edd4de52084b40f3615a76aabfb3c2605695a25d64a84e376a7e52ec447194e8b2c728272b3c71547bc4bebe275d97d5141faed5277087607e4b2a10875a0012f22f54b042ec7792dbe7e7404e46e0b455b82be5bf1e8e15bb3c1b3954340611ab59052eb8cfa2b398ab546c4ca90070147d82186f9f9282ca6edcf9fea147ca024d4b19027e418c19aa4d069c59a4f6af604131e80a39c7d39a92c1706a0a22d495db7ec90237bf17819ca1022a192922aa",
///     "ratchet_tree": null,
///     "initial_epoch_authenticator": "37db18cb065dbadd2dc9baedf1d29fffebddfd66cbe9d4c928bd3cbf1da4f1ed",
///     "epochs": []
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
    for file in TEST_VECTORS_PATH_READ {
        let scenario: Vec<PassiveClientWelcomeTestVector> = read(file);

        info!("# {file}");
        for (i, test_vector) in scenario.into_iter().enumerate() {
            info!("## {i:04} START");
            run_test_vector(test_vector);
            info!("## {i:04} END");
        }
    }
}

pub fn run_test_vector(test_vector: PassiveClientWelcomeTestVector) {
    let _ = pretty_env_logger::try_init();

    let backend = OpenMlsRustCrypto::default();
    let crypto = backend.crypto();

    let cipher_suite = test_vector.cipher_suite.try_into().unwrap();
    if crypto.supports(cipher_suite).is_err() {
        warn!("Skipping {}", cipher_suite);
        return;
    }

    let group_config = MlsGroupConfig::builder()
        .crypto_config(CryptoConfig::with_default_version(cipher_suite))
        .use_ratchet_tree_extension(true)
        .wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .build();

    let mut passive_client = PassiveClient::new(group_config, test_vector.external_psks.clone());

    passive_client.inject_key_package(
        test_vector.key_package,
        test_vector.signature_priv,
        test_vector.encryption_priv,
        test_vector.init_priv,
    );

    let ratchet_tree: Option<RatchetTree> = test_vector
        .ratchet_tree
        .as_ref()
        .map(|bytes| RatchetTree::tls_deserialize_exact(bytes.0.as_slice()).unwrap());

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
            // TODO(#1330)
            if passive_client.process_message(message) == Err(ProcessResult::Skip) {
                return;
            }
        }

        let message = MlsMessageIn::tls_deserialize_exact(&epoch.commit).unwrap();
        debug!("Commit: {message:#?}");
        // TODO(#1330)
        if passive_client.process_message(message) == Err(ProcessResult::Skip) {
            return;
        }

        assert_eq!(
            epoch.epoch_authenticator,
            passive_client.epoch_authenticator()
        );
    }
}

#[test]
fn test_write_vectors() {
    let backend = OpenMlsRustCrypto::default();
    let crypto = backend.crypto();

    let mut tests = Vec::new();

    for _ in 0..NUM_TESTS {
        for &ciphersuite in crypto.supported_ciphersuites().iter() {
            let test = generate_test_vector(ciphersuite);
            tests.push(test);
        }
    }

    // TODO(#1279)
    write(TEST_VECTOR_PATH_WRITE[0], &tests);
}

struct PassiveClient {
    backend: OpenMlsRustCrypto,
    group_config: MlsGroupConfig,
    group: Option<MlsGroup>,
}

// TODO(#1330)
#[derive(Clone, Debug, Eq, PartialEq)]
enum ProcessResult {
    Skip,
}

impl PassiveClient {
    fn new(group_config: MlsGroupConfig, psks: Vec<ExternalPskTest>) -> Self {
        let backend = OpenMlsRustCrypto::default();

        // Load all PSKs into key store.
        for psk in psks.into_iter() {
            // TODO: Better API?
            // We only construct this to easily save the PSK in the keystore.
            // The nonce is not saved, so it can be empty...
            let psk_id = PreSharedKeyId::external(psk.psk_id, vec![]);
            psk_id
                .write_to_key_store(&backend, group_config.crypto_config.ciphersuite, &psk.psk)
                .unwrap();
        }

        Self {
            backend,
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
                MlsMessageInBody::KeyPackage(key_package) => key_package,
                _ => panic!(),
            }
        };

        let init_priv = HpkePrivateKey::from(init_priv);

        let key_package_bundle = KeyPackageBundle {
            key_package: key_package.clone(),
            private_key: init_priv,
        };

        // Store key package.
        self.backend
            .key_store()
            .store(
                key_package
                    .hash_ref(self.backend.crypto())
                    .unwrap()
                    .as_slice(),
                &key_package,
            )
            .unwrap();

        // Store init key.
        self.backend
            .key_store()
            .store::<HpkePrivateKey>(
                key_package.hpke_init_key().as_slice(),
                key_package_bundle.private_key(),
            )
            .unwrap();

        // Store encryption key
        let key_pair = EncryptionKeyPair::from((
            key_package.leaf_node().encryption_key().clone(),
            EncryptionPrivateKey::from(encryption_priv),
        ));

        key_pair.write_to_key_store(&self.backend).unwrap();
    }

    fn join_by_welcome(
        &mut self,
        mls_message_welcome: MlsMessageIn,
        ratchet_tree: Option<RatchetTree>,
    ) {
        let group = MlsGroup::new_from_welcome(
            &self.backend,
            &self.group_config,
            mls_message_welcome.into_welcome().unwrap(),
            ratchet_tree,
        )
        .unwrap();

        self.group = Some(group);
    }

    fn process_message(&mut self, message: MlsMessageIn) -> Result<(), ProcessResult> {
        let processed_message = self
            .group
            .as_mut()
            .unwrap()
            .process_message(&self.backend, message.into_protocol_message().unwrap());

        // TODO(#1330)
        let processed_message = match processed_message {
            error @ Err(ProcessMessageError::InvalidCommit(
                StageCommitError::ProposalValidationError(ProposalValidationError::Psk(
                    PskError::Unsupported,
                )),
            )) => {
                warn!("Skipping `{:?}`.", error);
                return Err(ProcessResult::Skip);
            }
            _ => processed_message.unwrap(),
        };

        match processed_message.into_content() {
            ProcessedMessageContent::ProposalMessage(queued_proposal) => {
                self.group
                    .as_mut()
                    .unwrap()
                    .store_pending_proposal(*queued_proposal);
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                self.group
                    .as_mut()
                    .unwrap()
                    .merge_staged_commit(&self.backend, *staged_commit)
                    .unwrap();
            }
            _ => unimplemented!(),
        }

        Ok(())
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

pub fn generate_test_vector(cipher_suite: Ciphersuite) -> PassiveClientWelcomeTestVector {
    let creator_backend = OpenMlsRustCrypto::default();
    let crypto = creator_backend.crypto();

    let group_config = MlsGroupConfig::builder()
        .crypto_config(CryptoConfig::with_default_version(cipher_suite))
        .use_ratchet_tree_extension(true)
        .build();

    let creator =
        generate_group_candidate(b"Alice (Creator)", cipher_suite, Some(&creator_backend));

    let mut creator_group = MlsGroup::new(
        &creator_backend,
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
        cipher_suite,
        None::<&OpenMlsRustCrypto>,
    );

    let (_, mls_message_welcome, _) = creator_group
        .add_members(
            &creator_backend,
            &creator.signature_keypair,
            &[passive.key_package.clone()],
        )
        .unwrap();

    creator_group
        .merge_pending_commit(&creator_backend)
        .unwrap();

    let initial_epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

    let epoch1 = update_inline(&creator_backend, &creator, &mut creator_group);

    let epoch2 = {
        let proposals = vec![propose_add(
            cipher_suite,
            &creator_backend,
            &creator,
            &mut creator_group,
            b"Charlie",
        )];

        let commit = commit(&creator_backend, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epoch3 = {
        let proposals = vec![propose_remove(
            crypto,
            &creator,
            &mut creator_group,
            b"Charlie",
        )];

        let commit = commit(&creator_backend, &creator, &mut creator_group);

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
                cipher_suite,
                &creator_backend,
                &creator,
                &mut creator_group,
                b"Daniel",
            ),
            propose_add(
                cipher_suite,
                &creator_backend,
                &creator,
                &mut creator_group,
                b"Evelin",
            ),
        ];

        let commit = commit(&creator_backend, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epoch5 = {
        let proposals = vec![
            propose_remove(crypto, &creator, &mut creator_group, b"Daniel"),
            propose_add(
                cipher_suite,
                &creator_backend,
                &creator,
                &mut creator_group,
                b"Fardi",
            ),
        ];

        let commit = commit(&creator_backend, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epoch6 = {
        let proposals = vec![
            propose_remove(crypto, &creator, &mut creator_group, b"Fardi"),
            propose_remove(crypto, &creator, &mut creator_group, b"Evelin"),
        ];

        let commit = commit(&creator_backend, &creator, &mut creator_group);

        let epoch_authenticator = creator_group.epoch_authenticator().as_slice().to_vec();

        TestEpoch {
            proposals,
            commit,
            epoch_authenticator,
        }
    };

    let epochs = vec![epoch1, epoch2, epoch3, epoch4, epoch5, epoch6];

    PassiveClientWelcomeTestVector {
        cipher_suite: cipher_suite.into(),
        external_psks: vec![],

        key_package: MlsMessageOut::from(passive.key_package)
            .tls_serialize_detached()
            .unwrap(),

        signature_priv: passive.signature_keypair.private().to_vec(),
        encryption_priv: passive
            .encryption_keypair
            .private_key()
            .key()
            .as_slice()
            .to_vec(),
        init_priv: passive.init_keypair.private,

        welcome: mls_message_welcome.tls_serialize_detached().unwrap(),
        ratchet_tree: None,
        initial_epoch_authenticator,

        epochs,
    }
}

// -------------------------------------------------------------------------------------------------

fn propose_add(
    cipher_suite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    candidate: &GroupCandidate,
    group: &mut MlsGroup,
    add_identity: &[u8],
) -> TestProposal {
    let crypto = backend.crypto();

    let add_candidate =
        generate_group_candidate(add_identity, cipher_suite, None::<&OpenMlsRustCrypto>);

    let mls_message_out_proposal = group
        .propose_add_member(
            crypto,
            &candidate.signature_keypair,
            &add_candidate.key_package,
        )
        .unwrap();
    group.merge_pending_commit(backend).unwrap();

    TestProposal(mls_message_out_proposal.tls_serialize_detached().unwrap())
}

fn propose_remove(
    crypto: &impl OpenMlsCrypto,
    candidate: &GroupCandidate,
    group: &mut MlsGroup,
    remove_identity: &[u8],
) -> TestProposal {
    let remove = group
        .members()
        .find(|Member { credential, .. }| credential.identity() == remove_identity)
        .unwrap()
        .index;

    let mls_message_out_proposal = group
        .propose_remove_member(crypto, &candidate.signature_keypair, remove)
        .unwrap();

    TestProposal(mls_message_out_proposal.tls_serialize_detached().unwrap())
}

fn commit(backend: &OpenMlsRustCrypto, creator: &GroupCandidate, group: &mut MlsGroup) -> Vec<u8> {
    let (mls_message_out_commit, _, _) = group
        .commit_to_pending_proposals(backend, &creator.signature_keypair)
        .unwrap();
    group.merge_pending_commit(backend).unwrap();

    mls_message_out_commit.tls_serialize_detached().unwrap()
}

fn update_inline(
    backend: &OpenMlsRustCrypto,
    candidate: &GroupCandidate,
    group: &mut MlsGroup,
) -> TestEpoch {
    let (mls_message_out_commit, _, _) = group
        .self_update(backend, &candidate.signature_keypair)
        .unwrap();
    group.merge_pending_commit(backend).unwrap();

    let proposals = vec![];

    let commit = mls_message_out_commit.tls_serialize_detached().unwrap();

    let epoch_authenticator = group.epoch_authenticator().as_slice().to_vec();

    TestEpoch {
        proposals,
        commit,
        epoch_authenticator,
    }
}
