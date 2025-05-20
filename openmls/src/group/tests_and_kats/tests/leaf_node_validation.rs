use openmls_test::openmls_test;
use tls_codec::{Deserialize as _, Serialize as _};

use crate::{
    framing::*,
    group::*,
    test_utils::{frankenstein, single_group_test_framework::*},
    treesync::errors::UpdatePathError,
};

impl frankenstein::FrankenMlsMessage {
    /// Create a FrankenMlsMessage from the provided MlsMessageOut,
    /// with the specified LeafNodeSource.
    fn with_leaf_node_source<P: OpenMlsProvider>(
        member: &MemberState<'_, P>,
        mls_message_out: MlsMessageOut,
        leaf_node_source: frankenstein::FrankenLeafNodeSource,
    ) -> Self {
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
                update_path_in.leaf_node.payload.leaf_node_source = leaf_node_source;
            }
            None => unreachable!(),
        }

        let body = frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
            path,
            proposals,
        });

        let group_context = member.group.export_group_context().clone();
        let commit_content = frankenstein::FrankenFramedContent {
            body,
            group_id,
            epoch,
            sender,
            authenticated_data,
        };

        let secrets = member.group.message_secrets();
        let membership_key = secrets.membership_key().as_slice();

        frankenstein::FrankenMlsMessage {
            version,
            body: frankenstein::FrankenMlsMessageBody::PublicMessage(
                frankenstein::FrankenPublicMessage::auth(
                    &member.party.core_state.provider,
                    member.group.ciphersuite(),
                    &member.party.signer,
                    commit_content,
                    Some(&group_context.into()),
                    Some(membership_key),
                    confirmation_tag,
                ),
            ),
        }
    }
}

impl<P: OpenMlsProvider> GroupState<'_, P> {
    /// Test that the correct error variant is returned when a message is processed whose
    /// leaf_node_source does not have the type Commit.
    fn test_valn_1207(
        &mut self,
        mls_message_out: &MlsMessageOut,
        leaf_node_source: frankenstein::FrankenLeafNodeSource,
    ) {
        let [alice, bob] = self.members_mut(&["alice", "bob"]);
        let franken_commit = frankenstein::FrankenMlsMessage::with_leaf_node_source(
            alice,
            mls_message_out.clone(),
            leaf_node_source,
        );
        let fake_commit = MlsMessageIn::tls_deserialize(
            &mut franken_commit.tls_serialize_detached().unwrap().as_slice(),
        )
        .unwrap();
        let protocol_message = fake_commit.try_into_protocol_message().unwrap();

        let err = bob
            .group
            .process_message(&bob.party.core_state.provider, protocol_message)
            .expect_err("should return an error");

        assert_eq!(
            err,
            ProcessMessageError::ValidationError(ValidationError::UpdatePathError(
                UpdatePathError::InvalidType
            ))
        );
    }
}

/// This test makes sure that validation check 1207 (valn1207) is performed:
///
///   If the path value is populated, validate it and apply it to the tree:
///   Validate the LeafNode as specified in Section 7.3. The leaf_node_source
///   field MUST be set to commit.
///
///   We test whether the correct error is returned when the leaf_node_source
///   is set to `Update`.
#[openmls_test]
fn valn1207() {
    // Set up parties
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    let charlie_key_package = charlie_pre_group.key_package_bundle.key_package().clone();

    // Set up a new group with Alice
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

    let mut group_state = GroupState::new_from_party(
        group_id,
        alice_party.generate_pre_group(ciphersuite),
        create_config,
    )
    .unwrap();

    // Add Bob to group
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_party.generate_pre_group(ciphersuite)],
            join_config,
            tree: None,
        })
        .expect("Could not add member");
    let [alice] = group_state.members_mut(&["alice"]);

    // Alice creates commit to add Charlie to group
    let (mls_message_out, _welcome, _group_info) = alice
        .group
        .add_members(
            &alice_party.provider,
            &alice.party.signer,
            &[charlie_key_package],
        )
        .unwrap();

    // Test that correct error returned
    group_state.test_valn_1207(
        &mls_message_out,
        frankenstein::FrankenLeafNodeSource::Update,
    );
    group_state.test_valn_1207(
        &mls_message_out,
        frankenstein::FrankenLeafNodeSource::KeyPackage(frankenstein::FrankenLifetime {
            not_before: 0,
            not_after: 1,
        }),
    );
}
