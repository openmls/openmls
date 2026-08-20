//! Test for CommitBuilder AAD support via `with_aad`.

use openmls_test::openmls_test;
use tls_codec::{Deserialize, Serialize};

use crate::{
    framing::MlsMessageIn,
    group::{GroupId, MlsGroupCreateConfig, PURE_PLAINTEXT_WIRE_FORMAT_POLICY},
    test_utils::single_group_test_framework::{AddMemberConfig, CorePartyState, GroupState},
};

/// Test that a regular commit built with `with_aad` carries the AAD through to receivers.
///
/// 1. Create Alice and Bob in a plaintext group.
/// 2. Alice builds a commit with `with_aad(b"hello aad")`.
/// 3. Bob processes the commit and observes the AAD on the `ProcessedMessage`.
#[openmls_test]
fn commit_builder_with_aad() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let join_config = create_config.join_config().clone();

    let group_id = GroupId::from_slice(b"test-commit-builder-aad");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, create_config).unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config,
            tree: None,
        })
        .expect("Could not add member");

    let aad_payload = b"hello aad".to_vec();

    // Alice builds a commit carrying custom AAD.
    let [alice] = group_state.members_mut(&["alice"]);
    let bundle = alice
        .build_commit_and_stage(|builder| builder.with_aad(aad_payload.clone()))
        .expect("building a commit with AAD should succeed");

    // Bob processes the commit and checks the AAD.
    let [bob] = group_state.members_mut(&["bob"]);
    let wire_msg = bundle
        .commit()
        .tls_serialize_detached()
        .expect("serialization should succeed");
    let msg_in = MlsMessageIn::tls_deserialize(&mut &wire_msg[..])
        .expect("deserialization should succeed");
    let protocol_message = msg_in
        .try_into_protocol_message()
        .expect("should be a protocol message");

    let processed = bob
        .group
        .process_message(&bob.party.core_state.provider, protocol_message)
        .expect("Bob should be able to process Alice's commit");

    assert_eq!(
        processed.aad(),
        aad_payload.as_slice(),
        "the AAD on the processed message should match what Alice set"
    );
}
