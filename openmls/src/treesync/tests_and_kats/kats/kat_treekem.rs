use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsCryptoProvider;
use serde::{Deserialize, Serialize};
use tls_codec::Deserialize as TlsDeserializeTrait;

use crate::{
    binary_tree::LeafNodeIndex,
    extensions::RatchetTreeExtension,
    group::GroupId,
    test_utils::read,
    treesync::node::leaf_node::{LeafNodeTbs, TreeInfoTbs, VerifiableLeafNode}, prelude_test::Verifiable,
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PathSecret {
    node: u32,
    #[serde(with = "hex::serde")]
    path_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeavesPrivate {
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

    pub leaves_private: Vec<LeavesPrivate>,
    pub update_paths: Vec<Path>,
}

pub fn run_test_vector(test: TreeKemTest, backend: &impl OpenMlsCryptoProvider) -> () {
    let ratchet_tree =
        RatchetTreeExtension::tls_deserialize(&mut test.ratchet_tree.as_slice()).unwrap();

    // let mut treekems = vec![];
    // for leaf_private in test.leaves_private {
    //     let treekem
    // }
}

#[test]
fn read_test_vectors_treekem() {
    let tests: Vec<TreeKemTest> = read("test_vectors/treekem.json");

    let backend = OpenMlsRustCrypto::default();

    for test in tests {
        run_test_vector(test, &backend);
    }
}
