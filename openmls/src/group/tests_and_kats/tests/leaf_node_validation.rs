use openmls_test::openmls_test;
use tls_codec::{Deserialize as _, Serialize as _};

use crate::{
    framing::*,
    group::*,
    test_utils::{frankenstein, single_group_test_framework::*},
    treesync::errors::UpdatePathError,
};

#[openmls_test]
fn valn1207() {
    let group_id = GroupId::from_slice(b"Test Group");

    let create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(WireFormatPolicy::new(
            OutgoingWireFormatPolicy::AlwaysPlaintext,
            IncomingWireFormatPolicy::Mixed,
        ))
        .use_ratchet_tree_extension(true)
        .build();

    let join_config = create_config.join_config().clone();

    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let charlie_key_package = charlie_pre_group.key_package_bundle.key_package().clone();

    let mut group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        create_config,
    )
    .unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_party.generate_pre_group(ciphersuite)],
            join_config,
            tree: None,
        })
        .expect("Could not add member");
    let [alice] = group_state.members_mut(&["alice"]);

    let (mls_message_out, _welcome, _group_info) = alice
        .group
        .add_members(
            &alice_party.provider,
            &alice.party.signer,
            &[charlie_key_package],
        )
        .unwrap();

    // extract values we need later
    let frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content:
                    frankenstein::FrankenFramedContent {
                        group_id,
                        epoch,
                        sender,
                        authenticated_data,
                        body:
                            frankenstein::FrankenFramedContentBody::Commit(
                                frankenstein::FrankenCommit {
                                    mut path,
                                    proposals,
                                },
                            ),
                    },
                auth:
                    frankenstein::FrankenFramedContentAuthData {
                        signature: _,
                        confirmation_tag,
                    },
                ..
            }),
    } = frankenstein::FrankenMlsMessage::from(mls_message_out)
    else {
        unreachable!()
    };

    match path {
        Some(ref mut update_path_in) => {
            update_path_in.leaf_node.payload.leaf_node_source =
                frankenstein::FrankenLeafNodeSource::Update
        }
        None => unreachable!(),
    }

    let body = frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
        path,
        proposals,
    });

    let group_context = alice.group.export_group_context().clone();
    let commit_content = frankenstein::FrankenFramedContent {
        body,
        group_id,
        epoch,
        sender,
        authenticated_data,
    };

    let secrets = alice.group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    let franken_commit = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &alice_party.provider,
                ciphersuite,
                &alice.party.signer,
                commit_content,
                Some(&group_context.into()),
                Some(membership_key),
                confirmation_tag,
            ),
        ),
    };

    let fake_commit = MlsMessageIn::tls_deserialize(
        &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
    )
    .unwrap();
    let protocol_message = fake_commit.try_into_protocol_message().unwrap();

    let [bob] = group_state.members_mut(&["bob"]);

    let err = bob
        .group
        .process_message(&bob_party.provider, protocol_message)
        .expect_err("should return an error");

    assert_eq!(
        err,
        ProcessMessageError::ValidationError(ValidationError::UpdatePathError(
            UpdatePathError::InvalidType
        ))
    );
}
