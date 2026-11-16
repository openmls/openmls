//! A proposal that an application removed from the pending proposals must not
//! be committed, even if it was received more than once.
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as _, Serialize as _};

fn credential(name: &[u8], ciphersuite: Ciphersuite) -> (CredentialWithKey, SignatureKeyPair) {
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();
    let credential = CredentialWithKey {
        credential: BasicCredential::new(name.to_vec()).into(),
        signature_key: signer.public().into(),
    };
    (credential, signer)
}

#[test]
fn removed_proposal_is_not_committed() {
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let alice = OpenMlsRustCrypto::default();
    let bob = OpenMlsRustCrypto::default();
    let charlie = OpenMlsRustCrypto::default();
    let (alice_credential, alice_signer) = credential(b"alice", ciphersuite);
    let (bob_credential, bob_signer) = credential(b"bob", ciphersuite);
    let (charlie_credential, charlie_signer) = credential(b"charlie", ciphersuite);

    let mut alice_group = MlsGroup::new(
        &alice,
        &alice_signer,
        &MlsGroupCreateConfig::default(),
        alice_credential,
    )
    .unwrap();
    let bob_key_package = KeyPackage::builder()
        .build(ciphersuite, &bob, &bob_signer, bob_credential)
        .unwrap();
    let charlie_key_package = KeyPackage::builder()
        .build(ciphersuite, &charlie, &charlie_signer, charlie_credential)
        .unwrap();

    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            &alice,
            &alice_signer,
            &[bob_key_package.key_package().clone()],
        )
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    let welcome = MlsMessageIn::tls_deserialize_exact(welcome.tls_serialize_detached().unwrap())
        .unwrap()
        .into_welcome()
        .unwrap();
    let mut bob_group = StagedWelcome::new_from_welcome(
        &bob,
        &MlsGroupJoinConfig::default(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .unwrap()
    .into_group(&bob)
    .unwrap();

    // Bob proposes to add Charlie, twice. Both messages carry the same
    // proposal reference.
    let (first_message, first_ref) = bob_group
        .propose_add_member(&bob, &bob_signer, charlie_key_package.key_package())
        .unwrap();
    let (second_message, second_ref) = bob_group
        .propose_add_member(&bob, &bob_signer, charlie_key_package.key_package())
        .unwrap();
    assert_eq!(first_ref, second_ref);

    // Alice receives both and stores them as pending proposals.
    for message in [first_message, second_message] {
        let message =
            MlsMessageIn::tls_deserialize_exact(message.tls_serialize_detached().unwrap())
                .unwrap()
                .try_into_protocol_message()
                .unwrap();
        let processed = alice_group.process_message(&alice, message).unwrap();
        let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
            panic!("expected a proposal");
        };
        alice_group
            .store_pending_proposal(alice.storage(), *proposal)
            .unwrap();
    }
    assert_eq!(alice_group.pending_proposals().count(), 2);

    // Alice's application rejects the proposal.
    alice_group
        .remove_pending_proposal(alice.storage(), &first_ref)
        .unwrap();
    assert_eq!(alice_group.pending_proposals().count(), 0);

    // The stored group agrees: it loads and has no pending proposals.
    let loaded = MlsGroup::load(alice.storage(), alice_group.group_id())
        .unwrap()
        .expect("the group is in the storage");
    assert_eq!(loaded.pending_proposals().count(), 0);

    // A commit to the pending proposals doesn't add Charlie.
    let (_commit, welcome, _group_info) = alice_group
        .commit_to_pending_proposals(&alice, &alice_signer)
        .unwrap();
    alice_group.merge_pending_commit(&alice).unwrap();
    assert!(welcome.is_none());
    assert_eq!(alice_group.members().count(), 2);
}
