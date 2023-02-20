use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use tls_codec::Deserialize as TlsDeserializeTrait;

use crate::{
    binary_tree::LeafNodeIndex,
    credentials::{Credential, CredentialType, CredentialWithKey},
    extensions::{Extensions, RatchetTreeExtension},
    group::{config::CryptoConfig, GroupId},
    prelude_test::Verifiable,
    test_utils::read,
    tree::tests_and_kats::kats::secret_tree::Leaf,
    treesync::{
        self,
        node::leaf_node::{Capabilities, LeafNodeTbs, Lifetime, TreeInfoTbs, VerifiableLeafNode},
        TreeSync,
    },
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PathSecret {
    node: u32,
    #[serde(with = "hex::serde")]
    path_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeafPrivate {
    index: u32,
    #[serde(with = "hex::serde")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature_priv: Vec<u8>,
    path_secrets: Vec<PathSecret>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Path {
    sender: u32,
    #[serde(with = "hex::serde")]
    update_path: Vec<u8>,
    path_secrets: Vec<Option<String>>,
    #[serde(with = "hex::serde")]
    commit_secret: Vec<u8>,
    #[serde(with = "hex::serde")]
    tree_hash_after: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TreeKemTest {
    pub cipher_suite: u16,

    #[serde(with = "hex::serde")]
    pub group_id: Vec<u8>,
    pub epoch: u64,
    #[serde(with = "hex::serde")]
    pub confirmed_transcript_hash: Vec<u8>,

    #[serde(with = "hex::serde")]
    pub ratchet_tree: Vec<u8>, // RatchetTreeExtension

    pub leaves_private: Vec<LeafPrivate>,
    pub update_paths: Vec<Path>,
}

pub fn run_test_vector(test: TreeKemTest, backend: &impl OpenMlsCryptoProvider) -> () {
    let ciphersuite = Ciphersuite::try_from(test.cipher_suite).unwrap();
    if !backend
        .crypto()
        .supported_ciphersuites()
        .contains(&ciphersuite)
    {
        log::debug!("Skipping unsupported ciphersuite {ciphersuite:?}");
        return;
    }
    log::debug!("Testing ciphersuite {ciphersuite:?}");

    // Build public tree
    let ratchet_tree =
        RatchetTreeExtension::tls_deserialize(&mut test.ratchet_tree.as_slice()).unwrap();
    let treesync = TreeSync::from_nodes(backend, ciphersuite, ratchet_tree.as_slice()).unwrap();

    let mut treekems = vec![];
    for (leaf_index, leaf_private) in test.leaves_private.into_iter().enumerate() {
        let signature_key = treesync
            .leaf(LeafNodeIndex::new(leaf_index as u32))
            .unwrap()
            .signature_key();
        let signer = SignatureKeyPair::from_raw(
            ciphersuite.signature_algorithm(),
            leaf_private.signature_priv,
            signature_key.as_slice().to_vec(),
        );
        let credential_with_key = CredentialWithKey {
            credential: Credential::new("id".into(), CredentialType::Basic).unwrap(),
            signature_key: signature_key.clone(),
        };
        let (treekem, commit_secret, encryption_key_pair) = TreeSync::new(
            backend,
            &signer,
            CryptoConfig {
                ciphersuite,
                version: crate::versions::ProtocolVersion::Mls10,
            },
            credential_with_key,
            Lifetime::new(500),
            Capabilities::default(),
            Extensions::default(),
        )
        .unwrap();

        treekems.push(treekem);
    }
}

#[test]
fn read_test_vectors_treekem() {
    let tests: Vec<TreeKemTest> = read("test_vectors/treekem.json");

    let backend = OpenMlsRustCrypto::default();

    for test in tests {
        run_test_vector(test, &backend);
    }
}
