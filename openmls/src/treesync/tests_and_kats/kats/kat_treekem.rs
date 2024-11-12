use std::collections::HashSet;

use log::{debug, trace};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, types::Ciphersuite, OpenMlsProvider};
use serde::{Deserialize, Serialize};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

use crate::{
    binary_tree::{array_representation::ParentNodeIndex, LeafNodeIndex},
    extensions::{Extensions, RatchetTreeExtension},
    group::{create_commit::CommitType, GroupContext, GroupEpoch, GroupId},
    messages::PathSecret,
    prelude_test::Secret,
    schedule::CommitSecret,
    test_utils::{hex_to_bytes, OpenMlsRustCrypto},
    treesync::{
        node::{encryption_keys::EncryptionKeyPair, leaf_node::UpdateLeafNodeParams},
        treekem::{DecryptPathParams, UpdatePath, UpdatePathIn},
        TreeSync,
    },
};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PathSecretTest {
    node: u32,
    #[serde(with = "hex::serde")]
    path_secret: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LeafPrivateTest {
    index: u32,
    #[serde(with = "hex::serde")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex::serde")]
    signature_priv: Vec<u8>,
    path_secrets: Vec<PathSecretTest>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PathTest {
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

    pub leaves_private: Vec<LeafPrivateTest>,
    pub update_paths: Vec<PathTest>,
}

#[derive(Debug)]
struct LeafNodeInfoTest {
    index: LeafNodeIndex,
    encryption_keys: Vec<EncryptionKeyPair>,
    signature_keypair: SignatureKeyPair,
}

pub fn run_test_vector(test: TreeKemTest, provider: &impl OpenMlsProvider) {
    // Skip unsupported cipher suites (for now).
    let ciphersuite = Ciphersuite::try_from(test.cipher_suite).unwrap();

    if provider.crypto().supports(ciphersuite).is_err() {
        debug!("Skipping unsupported ciphersuite {ciphersuite:?}");
        return;
    }

    debug!("Testing ciphersuite {ciphersuite:?}");

    trace!("The tree has {} leaves.", test.leaves_private.len());

    let treesync = {
        let group_id = &GroupId::from_slice(test.group_id.as_slice());
        let ratchet_tree = RatchetTreeExtension::tls_deserialize_exact(test.ratchet_tree)
            .unwrap()
            .ratchet_tree()
            .clone()
            .into_verified(ciphersuite, provider.crypto(), group_id)
            .unwrap();

        TreeSync::from_ratchet_tree(provider.crypto(), ciphersuite, ratchet_tree).unwrap()
    };

    let full_leaf_nodes = {
        let mut full_leaf_nodes = vec![];

        for leaf_private_test in test.leaves_private.into_iter() {
            // * Associate encryption_priv and signature_priv with the leaf node
            let own_leaf = treesync
                .leaf(LeafNodeIndex::new(leaf_private_test.index))
                .unwrap();
            let signature_key = own_leaf.signature_key();
            let private_key = leaf_private_test.signature_priv.clone();
            let signature_keypair = SignatureKeyPair::from_raw(
                ciphersuite.signature_algorithm(),
                private_key,
                signature_key.as_slice().to_vec(),
            );

            // Collect all path key pairs
            let path_secrets_test = leaf_private_test.path_secrets;
            let mut encryption_keys = vec![EncryptionKeyPair::from_raw(
                own_leaf.encryption_key().as_slice().to_vec(),
                leaf_private_test.encryption_priv.clone(),
            )];

            for path_secret in path_secrets_test {
                let my_path_secret = PathSecret::from(Secret::from_slice(&path_secret.path_secret));
                let keypair = my_path_secret
                    .derive_key_pair(provider.crypto(), ciphersuite)
                    .unwrap();

                // Check that the public key matches the key in the tree.
                assert_eq!(
                    keypair.public_key(),
                    treesync
                        .parent(ParentNodeIndex::test_from_tree_index(path_secret.node))
                        .unwrap()
                        .encryption_key()
                );

                encryption_keys.push(keypair);
            }

            // Store the key pairs for decrypting the path later
            full_leaf_nodes.push(LeafNodeInfoTest {
                index: LeafNodeIndex::new(leaf_private_test.index),
                encryption_keys,
                signature_keypair,
            });
        }

        full_leaf_nodes
    };

    for path_test in test.update_paths.iter() {
        trace!("Processing update path sent from {}.", path_test.sender);

        let update_path =
            UpdatePath::from(UpdatePathIn::tls_deserialize_exact(&path_test.update_path).unwrap());

        let mut diff = treesync.empty_diff();
        diff.apply_received_update_path(
            provider.crypto(),
            ciphersuite,
            LeafNodeIndex::new(path_test.sender),
            &update_path,
        )
        .unwrap();

        // Check the parent hash in the diff is correct.
        assert!(diff
            .verify_parent_hashes(provider.crypto(), ciphersuite)
            .is_ok());

        // Merge the diff into a new tree.
        let staged_diff = diff
            .into_staged_diff(provider.crypto(), ciphersuite)
            .unwrap();
        let mut tree_after_kat = treesync.clone();
        tree_after_kat.merge_diff(staged_diff);

        // Check tree hash in new tree.
        assert_eq!(path_test.tree_hash_after, tree_after_kat.tree_hash());

        // Sanity check.
        assert_eq!(path_test.path_secrets.len(), treesync.leaf_count() as usize);

        // Construct a GroupContext object using the provided cipher_suite, group_id, epoch, and confirmed_transcript_hash, and the root tree hash of ratchet_tree
        // TODO(#1279): Update GroupContext.
        let group_context = GroupContext::new(
            ciphersuite,
            GroupId::from_slice(&test.group_id),
            GroupEpoch::from(test.epoch),
            tree_after_kat.tree_hash().into(),
            test.confirmed_transcript_hash.clone(),
            Extensions::default(),
        );

        // For each leaf node index j != i for which the leaf node is not blank:
        for leaf_i in full_leaf_nodes.iter() {
            // Process the update path for private_leaf[i]
            trace!("   Processing update path for leaf {}.", leaf_i.index.u32());

            if leaf_i.index.u32() == path_test.sender {
                trace!("       Skipping own leaf {}.", path_test.sender);
                // Don't do this for our own leaf.
                continue;
            }

            let commit_secret = apply_update_path(
                provider,
                ciphersuite,
                treesync.clone(),
                path_test.sender,
                path_test,
                &update_path,
                &group_context,
                leaf_i,
            );

            // Check that the commit secret is correct.
            assert_eq!(&path_test.commit_secret, commit_secret.as_slice());

            trace!("       Successfully checked all path secrets and the commit secret.");
        }

        trace!("--------------------------------------------");

        // Create a new `new_update_path`, using `ratchet_tree`, `leaves[i].signature_priv`,
        // and the group context computed above. Note the resulting `new_commit_secret`.
        let mut diff_after_kat = tree_after_kat.empty_diff();

        let (update_path, new_commit_secret) = {
            let signer = {
                let full_leaf = full_leaf_nodes
                    .iter()
                    .find(|node| node.index == LeafNodeIndex::new(path_test.sender))
                    .unwrap();

                SignatureKeyPair::from_raw(
                    ciphersuite.signature_algorithm(),
                    full_leaf.signature_keypair.private().to_vec(),
                    full_leaf.signature_keypair.to_public_vec(),
                )
            };

            let leaf_index = LeafNodeIndex::new(path_test.sender);
            let leaf_node = diff_after_kat.leaf(leaf_index).unwrap();
            let leaf_node_params = UpdateLeafNodeParams::derive(leaf_node);

            // TODO(#1279): Update own leaf.
            let (vec_plain_update_path_nodes, _, commit_secret) = diff_after_kat
                .apply_own_update_path(
                    provider.rand(),
                    provider.crypto(),
                    &signer,
                    ciphersuite,
                    &CommitType::Member,
                    group_context.group_id().clone(),
                    LeafNodeIndex::new(path_test.sender),
                    leaf_node_params,
                )
                .unwrap();

            // TODO(#1279): Update GroupContext.
            let serialized_group_context = group_context.tls_serialize_detached().unwrap();

            // Encrypt path to according recipients.
            let encrypted_path = diff_after_kat
                .encrypt_path(
                    provider.crypto(),
                    ciphersuite,
                    &vec_plain_update_path_nodes,
                    &serialized_group_context,
                    &HashSet::new(),
                    LeafNodeIndex::new(path_test.sender),
                )
                .unwrap();

            (
                UpdatePath::new(
                    diff_after_kat
                        .leaf(LeafNodeIndex::new(path_test.sender))
                        .unwrap()
                        .clone(),
                    encrypted_path,
                ),
                commit_secret,
            )
        };

        // For each leaf node index j != i for which the leaf node is not blank:
        //
        //     Process new_update_path using private_leaf[j]
        //     Verify that the resulting commit secret is new_commit_secret
        for leaf_i in full_leaf_nodes.iter() {
            trace!("   Processing self-update for leaf {}.", leaf_i.index.u32());

            if leaf_i.index.u32() == path_test.sender {
                continue;
            }

            let params = DecryptPathParams {
                update_path: update_path.nodes(),
                sender_leaf_index: LeafNodeIndex::new(path_test.sender),
                exclusion_list: &HashSet::default(),
                group_context: &group_context.tls_serialize_detached().unwrap(),
            };

            let (_encryption_keys, commit_secret_inner) = tree_after_kat
                .empty_diff()
                .decrypt_path(
                    provider.crypto(),
                    ciphersuite,
                    params,
                    &leaf_i.encryption_keys.iter().collect::<Vec<_>>(),
                    leaf_i.index,
                )
                .unwrap();

            trace!("       Successfully decrypted path secrets.");

            assert_eq!(new_commit_secret, commit_secret_inner);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_update_path(
    provider: &impl OpenMlsProvider,
    ciphersuite: Ciphersuite,
    treesync: TreeSync,
    sender: u32,
    path_test: &PathTest,
    update_path: &UpdatePath,
    group_context: &GroupContext,
    leaf_node_info_test: &LeafNodeInfoTest,
) -> CommitSecret {
    let params = DecryptPathParams {
        update_path: update_path.nodes(),
        sender_leaf_index: LeafNodeIndex::new(sender),
        exclusion_list: &HashSet::default(),
        group_context: &group_context.tls_serialize_detached().unwrap(),
    };

    let (encryption_keys, commit_secret) = treesync
        .empty_diff()
        .decrypt_path(
            provider.crypto(),
            ciphersuite,
            params,
            &leaf_node_info_test
                .encryption_keys
                .iter()
                .collect::<Vec<_>>(),
            leaf_node_info_test.index,
        )
        .unwrap();

    trace!("       Successfully decrypted path secrets.");

    let expected_keypair = {
        // Check that the path secrets are correct. We can only do this indirectly
        // by looking at the encryption keys.
        let expected_path_secret = path_test.path_secrets[leaf_node_info_test.index.usize()]
            .as_ref()
            .unwrap();

        let path_secret = PathSecret::from(Secret::from_slice(&hex_to_bytes(expected_path_secret)));

        path_secret
            .derive_key_pair(provider.crypto(), ciphersuite)
            .unwrap()
    };

    assert_eq!(encryption_keys[0], expected_keypair);

    commit_secret
}

#[test]
fn read_test_vectors_treekem() {
    let _ = pretty_env_logger::try_init();
    let tests: Vec<TreeKemTest> = read_json!("../../../../test_vectors/treekem.json");

    let provider = OpenMlsRustCrypto::default();

    for test in tests.into_iter() {
        run_test_vector(test, &provider);
    }
}
