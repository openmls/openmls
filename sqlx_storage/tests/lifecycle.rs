mod common;

use common::*;
use openmls_sqlx_storage::SqliteStorageProvider;
use openmls_traits::storage::StorageProvider;

#[tokio::test(flavor = "multi_thread")]
async fn proposals() {
    let group_id = TestGroupId(b"TestGroupId".to_vec());
    let proposals = (0..10)
        .map(|i| TestProposal(format!("TestProposal{i}").as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let mut storage = SqliteStorageProvider::<JsonCodec>::new(pool);

    storage.run_migrations().unwrap();

    for (i, proposal) in proposals.iter().enumerate() {
        storage
            .queue_proposal(&group_id, &TestProposalRef(i), proposal)
            .unwrap();
    }

    let proposal_refs_read: Vec<TestProposalRef> = storage.queued_proposal_refs(&group_id).unwrap();
    assert_eq!(
        (0..10).map(TestProposalRef).collect::<Vec<_>>(),
        proposal_refs_read
    );

    let proposals_read: Vec<(TestProposalRef, TestProposal)> =
        storage.queued_proposals(&group_id).unwrap();
    let proposals_expected: Vec<(TestProposalRef, TestProposal)> = (0..10)
        .map(TestProposalRef)
        .zip(proposals.clone())
        .collect();
    assert_eq!(proposals_expected, proposals_read);

    storage
        .remove_proposal(&group_id, &TestProposalRef(5))
        .unwrap();

    let proposal_refs_read: Vec<TestProposalRef> = storage.queued_proposal_refs(&group_id).unwrap();
    let mut expected = (0..10).map(TestProposalRef).collect::<Vec<_>>();
    expected.remove(5);
    assert_eq!(expected, proposal_refs_read);

    let proposals_read: Vec<(TestProposalRef, TestProposal)> =
        storage.queued_proposals(&group_id).unwrap();
    let mut proposals_expected: Vec<(TestProposalRef, TestProposal)> = (0..10)
        .map(TestProposalRef)
        .zip(proposals.clone())
        .collect();
    proposals_expected.remove(5);
    assert_eq!(proposals_expected, proposals_read);

    storage
        .clear_proposal_queue::<TestGroupId, TestProposalRef>(&group_id)
        .unwrap();
    let proposal_refs_read: Vec<TestProposalRef> = storage.queued_proposal_refs(&group_id).unwrap();
    assert!(proposal_refs_read.is_empty());

    let proposals_read: Vec<(TestProposalRef, TestProposal)> =
        storage.queued_proposals(&group_id).unwrap();
    assert!(proposals_read.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn group_data_roundtrip() {
    let group_id = TestGroupId(b"group-data".to_vec());
    let join_config = TestBlob(b"join-config".to_vec());
    let tree = TestBlob(b"tree".to_vec());
    let group_context = TestBlob(b"context".to_vec());
    let interim = TestBlob(b"interim".to_vec());
    let confirmation = TestBlob(b"confirmation".to_vec());
    let group_state = TestBlob(b"group-state".to_vec());
    let message_secrets = TestBlob(b"message-secrets".to_vec());
    let resumption = TestBlob(b"resumption".to_vec());
    let epoch_secrets = TestBlob(b"epoch-secrets".to_vec());
    let own_leaf_index = TestLeafIndex(42);
    let leaf_a = TestBlob(b"leaf-a".to_vec());
    let leaf_b = TestBlob(b"leaf-b".to_vec());

    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let mut storage = SqliteStorageProvider::<JsonCodec>::new(pool);
    storage.run_migrations().unwrap();

    storage
        .write_mls_join_config(&group_id, &join_config)
        .unwrap();
    let join_read: Option<TestBlob> = storage.mls_group_join_config(&group_id).unwrap();
    assert_eq!(Some(join_config.clone()), join_read);
    storage.delete_group_config(&group_id).unwrap();
    let join_after_delete: Option<TestBlob> = storage.mls_group_join_config(&group_id).unwrap();
    assert!(join_after_delete.is_none());

    storage.write_tree(&group_id, &tree).unwrap();
    let tree_read: Option<TestBlob> = storage.tree(&group_id).unwrap();
    assert_eq!(Some(tree.clone()), tree_read);
    storage.delete_tree(&group_id).unwrap();
    let tree_after_delete: Option<TestBlob> = storage.tree(&group_id).unwrap();
    assert!(tree_after_delete.is_none());

    storage.write_context(&group_id, &group_context).unwrap();
    let context_read: Option<TestBlob> = storage.group_context(&group_id).unwrap();
    assert_eq!(Some(group_context.clone()), context_read);
    storage.delete_context(&group_id).unwrap();
    let context_after_delete: Option<TestBlob> = storage.group_context(&group_id).unwrap();
    assert!(context_after_delete.is_none());

    storage
        .write_interim_transcript_hash(&group_id, &interim)
        .unwrap();
    let interim_read: Option<TestBlob> = storage.interim_transcript_hash(&group_id).unwrap();
    assert_eq!(Some(interim.clone()), interim_read);
    storage.delete_interim_transcript_hash(&group_id).unwrap();
    let interim_after_delete: Option<TestBlob> =
        storage.interim_transcript_hash(&group_id).unwrap();
    assert!(interim_after_delete.is_none());

    storage
        .write_confirmation_tag(&group_id, &confirmation)
        .unwrap();
    let confirmation_read: Option<TestBlob> = storage.confirmation_tag(&group_id).unwrap();
    assert_eq!(Some(confirmation.clone()), confirmation_read);
    storage.delete_confirmation_tag(&group_id).unwrap();
    let confirmation_after_delete: Option<TestBlob> = storage.confirmation_tag(&group_id).unwrap();
    assert!(confirmation_after_delete.is_none());

    storage.write_group_state(&group_id, &group_state).unwrap();
    let group_state_read: Option<TestBlob> = storage.group_state(&group_id).unwrap();
    assert_eq!(Some(group_state.clone()), group_state_read);
    storage.delete_group_state(&group_id).unwrap();
    let group_state_after_delete: Option<TestBlob> = storage.group_state(&group_id).unwrap();
    assert!(group_state_after_delete.is_none());

    storage
        .write_message_secrets(&group_id, &message_secrets)
        .unwrap();
    let message_secrets_read: Option<TestBlob> = storage.message_secrets(&group_id).unwrap();
    assert_eq!(Some(message_secrets.clone()), message_secrets_read);
    storage.delete_message_secrets(&group_id).unwrap();
    let message_secrets_after_delete: Option<TestBlob> =
        storage.message_secrets(&group_id).unwrap();
    assert!(message_secrets_after_delete.is_none());

    storage
        .write_resumption_psk_store(&group_id, &resumption)
        .unwrap();
    let resumption_read: Option<TestBlob> = storage.resumption_psk_store(&group_id).unwrap();
    assert_eq!(Some(resumption.clone()), resumption_read);
    storage
        .delete_all_resumption_psk_secrets(&group_id)
        .unwrap();
    let resumption_after_delete: Option<TestBlob> =
        storage.resumption_psk_store(&group_id).unwrap();
    assert!(resumption_after_delete.is_none());

    storage
        .write_group_epoch_secrets(&group_id, &epoch_secrets)
        .unwrap();
    let epoch_secrets_read: Option<TestBlob> = storage.group_epoch_secrets(&group_id).unwrap();
    assert_eq!(Some(epoch_secrets.clone()), epoch_secrets_read);
    storage.delete_group_epoch_secrets(&group_id).unwrap();
    let epoch_secrets_after_delete: Option<TestBlob> =
        storage.group_epoch_secrets(&group_id).unwrap();
    assert!(epoch_secrets_after_delete.is_none());

    storage
        .write_own_leaf_index(&group_id, &own_leaf_index)
        .unwrap();
    let own_index_read: Option<TestLeafIndex> = storage.own_leaf_index(&group_id).unwrap();
    assert_eq!(Some(own_leaf_index.clone()), own_index_read);
    storage.delete_own_leaf_index(&group_id).unwrap();
    let own_index_after_delete: Option<TestLeafIndex> = storage.own_leaf_index(&group_id).unwrap();
    assert!(own_index_after_delete.is_none());

    storage.append_own_leaf_node(&group_id, &leaf_a).unwrap();
    let leaf_nodes_read: Vec<TestBlob> = storage.own_leaf_nodes(&group_id).unwrap();
    assert_eq!(vec![leaf_a.clone()], leaf_nodes_read);

    storage.delete_own_leaf_nodes(&group_id).unwrap();
    storage.append_own_leaf_node(&group_id, &leaf_b).unwrap();
    let leaf_nodes_replaced: Vec<TestBlob> = storage.own_leaf_nodes(&group_id).unwrap();
    assert_eq!(vec![leaf_b.clone()], leaf_nodes_replaced);

    storage.delete_own_leaf_nodes(&group_id).unwrap();
    let leaf_nodes_after_delete: Vec<TestBlob> = storage.own_leaf_nodes(&group_id).unwrap();
    assert!(leaf_nodes_after_delete.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn key_material_roundtrip() {
    let group_id = TestGroupId(b"key-material-group".to_vec());
    let signature_public_key = TestSignaturePublicKey(b"signature-public".to_vec());
    let signature_key_pair = TestSignatureKeyPair(b"signature-key-pair".to_vec());
    let encryption_key = TestEncryptionKey(b"encryption-public".to_vec());
    let encryption_pair = TestHpkeKeyPair(b"encryption-pair".to_vec());
    let epoch = TestEpochKey(b"epoch".to_vec());
    let epoch_pairs = vec![
        TestHpkeKeyPair(b"epoch-pair-a".to_vec()),
        TestHpkeKeyPair(b"epoch-pair-b".to_vec()),
    ];
    let hash_ref = TestHashRef(b"hash-ref".to_vec());
    let key_package = TestKeyPackage(b"key-package".to_vec());
    let psk_id = TestPskId(b"psk-id".to_vec());
    let psk_bundle = TestPskBundle(b"psk-bundle".to_vec());
    let leaf_index: u32 = 7;

    let pool = sqlx::SqlitePool::connect("sqlite::memory:").await.unwrap();
    let mut storage = SqliteStorageProvider::<JsonCodec>::new(pool);
    storage.run_migrations().unwrap();

    storage
        .write_signature_key_pair(&signature_public_key, &signature_key_pair)
        .unwrap();
    let signature_pair_read: Option<TestSignatureKeyPair> =
        storage.signature_key_pair(&signature_public_key).unwrap();
    assert_eq!(Some(signature_key_pair.clone()), signature_pair_read);
    storage
        .delete_signature_key_pair(&signature_public_key)
        .unwrap();
    let signature_pair_after_delete: Option<TestSignatureKeyPair> =
        storage.signature_key_pair(&signature_public_key).unwrap();
    assert!(signature_pair_after_delete.is_none());

    storage
        .write_encryption_key_pair(&encryption_key, &encryption_pair)
        .unwrap();
    let encryption_pair_read: Option<TestHpkeKeyPair> =
        storage.encryption_key_pair(&encryption_key).unwrap();
    assert_eq!(Some(encryption_pair.clone()), encryption_pair_read);
    storage.delete_encryption_key_pair(&encryption_key).unwrap();
    let encryption_pair_after_delete: Option<TestHpkeKeyPair> =
        storage.encryption_key_pair(&encryption_key).unwrap();
    assert!(encryption_pair_after_delete.is_none());

    storage
        .write_encryption_epoch_key_pairs(&group_id, &epoch, leaf_index, &epoch_pairs)
        .unwrap();
    let epoch_pairs_read: Vec<TestHpkeKeyPair> = storage
        .encryption_epoch_key_pairs(&group_id, &epoch, leaf_index)
        .unwrap();
    assert_eq!(epoch_pairs.clone(), epoch_pairs_read);
    storage
        .delete_encryption_epoch_key_pairs(&group_id, &epoch, leaf_index)
        .unwrap();
    let epoch_pairs_after_delete: Vec<TestHpkeKeyPair> = storage
        .encryption_epoch_key_pairs(&group_id, &epoch, leaf_index)
        .unwrap();
    assert!(epoch_pairs_after_delete.is_empty());

    storage.write_key_package(&hash_ref, &key_package).unwrap();
    let key_package_read: Option<TestKeyPackage> = storage.key_package(&hash_ref).unwrap();
    assert_eq!(Some(key_package.clone()), key_package_read);
    storage.delete_key_package(&hash_ref).unwrap();
    let key_package_after_delete: Option<TestKeyPackage> = storage.key_package(&hash_ref).unwrap();
    assert!(key_package_after_delete.is_none());

    storage.write_psk(&psk_id, &psk_bundle).unwrap();
    let psk_bundle_read: Option<TestPskBundle> = storage.psk(&psk_id).unwrap();
    assert_eq!(Some(psk_bundle.clone()), psk_bundle_read);
    storage.delete_psk(&psk_id).unwrap();
    let psk_bundle_after_delete: Option<TestPskBundle> = storage.psk(&psk_id).unwrap();
    assert!(psk_bundle_after_delete.is_none());
}
