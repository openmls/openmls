use std::collections::HashSet;

use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsCryptoProvider};
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::{
    binary_tree::{array_representation::ParentNodeIndex, LeafNodeIndex},
    credentials::{Credential, CredentialType, CredentialWithKey},
    extensions::{Extensions, RatchetTreeExtension},
    group::{GroupContext, GroupEpoch, GroupId},
    messages::EncryptedGroupSecrets,
    prelude::LeafNode,
    prelude_test::Secret,
    test_utils::{hex_to_bytes, read},
    treesync::{
        node::encryption_keys::{EncryptionKey, EncryptionKeyPair},
        treekem::{DecryptPathParams, UpdatePath},
        TreeSync,
    },
    versions::ProtocolVersion,
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

    struct LeafNodeInfo {
        index: LeafNodeIndex,
        encryption_keys: Vec<EncryptionKeyPair>,
        encryption_keypair: EncryptionKeyPair,
        signature_keypair: SignatureKeyPair,
    };
    let mut full_leaf_nodes = vec![];

    for leaf_private in test.leaves_private.into_iter() {
        let mut treekem = treesync.clone();

        let own_leaf = treesync
            .leaf(LeafNodeIndex::new(leaf_private.index as u32))
            .unwrap();
        let signature_key = own_leaf.signature_key();
        let mut private_key = leaf_private.signature_priv.clone();
        private_key.append(&mut signature_key.as_slice().to_vec());
        let signature_keypair = SignatureKeyPair::from_raw(
            ciphersuite.signature_algorithm(),
            private_key,
            signature_key.as_slice().to_vec(),
        );
        let credential_with_key = CredentialWithKey {
            credential: Credential::new("id".into(), CredentialType::Basic).unwrap(),
            signature_key: signature_key.clone(),
        };

        let path_secrets = leaf_private.path_secrets;
        let mut encyrption_keys = vec![EncryptionKeyPair::from_raw(
            own_leaf.encryption_key().as_slice().to_vec(),
            leaf_private.encryption_priv.clone(),
        )];
        for path_secret in path_secrets {
            let my_path_secret = crate::messages::PathSecret::from(Secret::from_slice(
                &path_secret.path_secret,
                ProtocolVersion::Mls10,
                ciphersuite,
            ));
            let keypair = my_path_secret
                .derive_key_pair(backend, ciphersuite)
                .unwrap();

            // Check that the public key matches the key in the tree.
            assert_eq!(
                keypair.public_key(),
                treesync
                    .parent(ParentNodeIndex::from_tree_index(path_secret.node))
                    .unwrap()
                    .encryption_key()
            );

            encyrption_keys.push(keypair);
        }

        // Store the key pairs for decrypting the path later
        full_leaf_nodes.push(LeafNodeInfo {
            index: LeafNodeIndex::new(leaf_private.index),
            encryption_keys: encyrption_keys,
            encryption_keypair: EncryptionKeyPair::from_raw(
                own_leaf.encryption_key().as_slice().to_vec(),
                leaf_private.encryption_priv,
            ),
            signature_keypair,
        });
    }

    let group_context = GroupContext::new(
        ciphersuite,
        GroupId::from_slice(&test.group_id),
        GroupEpoch::from(test.epoch),
        treesync.tree_hash().into(),
        test.confirmed_transcript_hash.clone(),
        Extensions::default(),
    );

    for (i, path) in test.update_paths.iter().enumerate() {
        let update_path = UpdatePath::tls_deserialize(&mut path.update_path.as_slice()).unwrap();
        let mut diff = treesync.empty_diff();
        diff.apply_received_update_path(
            backend,
            ciphersuite,
            LeafNodeIndex::new(path.sender),
            &update_path,
        )
        .unwrap();

        // Check the parent hash in the diff is correct.
        assert!(diff.verify_parent_hashes(backend, ciphersuite).is_ok());

        // Merge the diff into a new tree.
        let staged_diff = diff.into_staged_diff(backend, ciphersuite).unwrap();
        let mut new_tree = treesync.clone();
        new_tree.merge_diff(staged_diff);

        // Check tree hash in new tree.
        assert_eq!(path.tree_hash_after, new_tree.tree_hash());

        assert_eq!(path.path_secrets.len(), treesync.leaf_count() as usize);
        for (j, leaf) in path.path_secrets.iter().enumerate() {
            // if let Some(leaf) = leaf {
            if j == 1 {
                // FIXME: skipping to the test we want -> remove
                continue;
            }
            if i != j {
                log::trace!("Processing update path for leaf {j}.");
                // Process the update path for private_leaf[j]
                let leaf_j = &full_leaf_nodes[j];
                assert_eq!(leaf_j.index.usize(), j);

                let group_context = GroupContext::new(
                    ciphersuite,
                    GroupId::from_slice(&test.group_id),
                    GroupEpoch::from(test.epoch + 1),
                    new_tree.tree_hash().into(),
                    test.confirmed_transcript_hash.clone(),
                    Extensions::default(),
                );

                let params = DecryptPathParams {
                    version: ProtocolVersion::Mls10,
                    update_path: update_path.nodes(),
                    sender_leaf_index: LeafNodeIndex::new(path.sender),
                    exclusion_list: &HashSet::default(),
                    group_context: &group_context.tls_serialize_detached().unwrap(),
                };

                let diff = treesync.empty_diff();

                log::trace!("sender_leaf_index: {:?}", params.sender_leaf_index.u32());

                diff.decrypt_path(
                    backend,
                    ciphersuite,
                    params,
                    &leaf_j.encryption_keys.iter().collect::<Vec<_>>(),
                    LeafNodeIndex::new(j as u32),
                )
                .unwrap();
            }
        }
    }
}

#[test]
fn read_test_vectors_treekem() {
    let _ = pretty_env_logger::try_init();
    let tests: Vec<TreeKemTest> = read("test_vectors/treekem.json");

    let backend = OpenMlsRustCrypto::default();

    for test in tests {
        run_test_vector(test, &backend);
    }
}
