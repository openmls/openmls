#![cfg(feature = "virtual-clients-draft")]
use openmls::{
    group::{GroupId, MlsGroup, MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
    prelude::{test_utils::new_credential, LeafNodeParameters, ProcessedMessageContent},
    test_utils::single_group_test_framework::{CorePartyState, GroupState},
};
use openmls_test::openmls_test;

mod mls_group;

#[openmls_test]
fn process_own_commits() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);

    let group_config = MlsGroupCreateConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let group_id = GroupId::from_slice(b"Test Group");

    let mut group_state =
        GroupState::new_from_party(group_id.clone(), alice_pre_group, group_config.clone())
            .unwrap();

    let [alice_group] = group_state.members_mut(&["alice"]);

    let message_bundle = alice_group
        .group
        .self_update(
            &alice_party.provider,
            &alice_group.party.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();

    group_state
        .deliver_and_apply(message_bundle.into_commit().into())
        .unwrap();
}

#[openmls_test::openmls_test]
fn processing_own_application_message() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    // === Alice creates a group ===
    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential.clone())
        .expect("An unexpected error occurred.");

    // Alice sends an application message and decrypts it herself
    let alice_message = b"Hello, this is Alice!";
    let (_generation, ciphertext) = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, alice_message)
        .unwrap();

    let processed_message = alice_group
        .process_message(
            alice_provider,
            ciphertext.clone().into_protocol_message().unwrap(),
        )
        .unwrap();

    let ProcessedMessageContent::ApplicationMessage(msg) = processed_message.into_content() else {
        panic!("Expected an application message.");
    };
    assert!(alice_message.as_slice() == msg.into_bytes().as_slice());

    // Decrypting the message again should fail because the generation has
    // already been ratcheted forward.
    let _ = alice_group
        .process_message(alice_provider, ciphertext.into_protocol_message().unwrap())
        .expect_err("Expected an error when processing the same message again.");

    // Alice sends another application message and confirms it. Trying to
    // decrypt it should then fail.
    let alice_message = b"Hello, this is Alice again!";
    let (generation, ciphertext) = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, alice_message)
        .unwrap();
    alice_group
        .confirm_message(alice_provider.storage(), generation)
        .unwrap();

    let _ = alice_group
        .process_message(
            alice_provider,
            ciphertext.clone().into_protocol_message().unwrap(),
        )
        .expect_err("Expected an error when processing a confirmed message.");
}

#[openmls_test::openmls_test]
fn old_unconfirmed_own_message_survives_later_confirmations() {
    let alice_provider = &Provider::default();

    let (alice_credential, alice_signer) =
        new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

    let mut alice_group = MlsGroup::builder()
        .ciphersuite(ciphersuite)
        .build(alice_provider, &alice_signer, alice_credential)
        .expect("An unexpected error occurred.");

    let first_message = b"first unconfirmed message";
    let (_first_generation, first_ciphertext) = alice_group
        .create_unconfirmed_message(alice_provider, &alice_signer, first_message)
        .expect("Could not create first unconfirmed message.");

    let tolerance = alice_group
        .configuration()
        .sender_ratchet_configuration()
        .out_of_order_tolerance();

    for i in 0..tolerance + 2 {
        let (generation, _) = alice_group
            .create_unconfirmed_message(
                alice_provider,
                &alice_signer,
                format!("later confirmed message {i}").as_bytes(),
            )
            .expect("Could not create later unconfirmed message.");
        alice_group
            .confirm_message(alice_provider.storage(), generation)
            .expect("Could not confirm later message.");
    }

    let processed_message = alice_group
        .process_message(
            alice_provider,
            first_ciphertext.into_protocol_message().unwrap(),
        )
        .expect("Expected old unconfirmed own message to decrypt.");

    let ProcessedMessageContent::ApplicationMessage(msg) = processed_message.into_content() else {
        panic!("Expected an application message.");
    };
    assert_eq!(first_message.as_slice(), msg.into_bytes().as_slice());
}
