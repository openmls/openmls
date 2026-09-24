use tls_codec::{Deserialize as _, Serialize as _};

use crate::prelude::*;
use crate::test_utils::{frankenstein, single_group_test_framework::*};
use crate::treesync::{
    errors::{ApplyOwnUpdatePathError, LeafNodeValidationError},
    node::leaf_node::LeafNodeBuildError,
};

// Helper macro for checking error matches a provided pattern
macro_rules! assert_err_matches {
    ($err:expr, $pattern:pat) => {
        assert!(matches!($err.expect_err("Expected an error"), $pattern));
    };
}

// Function to check that the correct error type was returned
fn expect_valn0104_error<Provider: OpenMlsProvider>(error: Result<(), GroupError<Provider>>) {
    assert_err_matches!(
        error,
        GroupError::<Provider>::AddMembers(AddMembersError::CreateCommitError(
            CreateCommitError::ProposalValidationError(
                ProposalValidationError::LeafNodeValidation(
                    LeafNodeValidationError::UnsupportedCredentials,
                )
            )
        ))
    );
}

impl<'a, 'b: 'a, Provider: OpenMlsProvider + Default> GroupState<'b, Provider> {
    // add a member to the GroupState with the specified credential capabilities
    fn add_member_with_credential_capabilities(
        &'a mut self,
        new_party: &'b CorePartyState<Provider>,
        adder_name: &'static str,
        ciphersuite: Ciphersuite,
        credential_types: Vec<CredentialType>,
    ) -> Result<(), GroupError<Provider>> {
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        // Initialize party and pre-group
        let mut pre_group = new_party.generate_pre_group(ciphersuite);

        // update the credential type of the credential
        pre_group.update_credential_capabilities(credential_types, ciphersuite);

        let add_member_config: AddMemberConfig<'_, Provider> = AddMemberConfig {
            adder: adder_name,
            addees: vec![pre_group],
            join_config,
            tree: None,
        };

        self.add_member(add_member_config)
    }

    // add a member to the GroupState with the specified credential type
    fn add_member_with_credential_type(
        &'a mut self,
        new_party: &'b CorePartyState<Provider>,
        adder_name: &'static str,
        ciphersuite: Ciphersuite,
        credential_type: CredentialType,
    ) -> Result<(), GroupError<Provider>> {
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();

        // Initialize party and pre-group
        let mut pre_group = new_party.generate_pre_group(ciphersuite);

        // update the credential type of the credential
        pre_group.update_credential_type(credential_type, ciphersuite);

        let add_member_config: AddMemberConfig<'_, Provider> = AddMemberConfig {
            adder: adder_name,
            addees: vec![pre_group],
            join_config,
            tree: None,
        };

        self.add_member(add_member_config)
    }
}

impl<'a, 'b: 'a, Provider: OpenMlsProvider> PreGroupPartyState<'b, Provider> {
    // Helper function to update the PreGroupPartyState to support the specified CredentialTypes in its Capabilities
    fn update_credential_capabilities(
        &'a mut self,
        credential_types: Vec<CredentialType>,
        ciphersuite: Ciphersuite,
    ) -> Capabilities {
        let capabilities = self
            .key_package_bundle
            .key_package
            .leaf_node()
            .capabilities();

        let new_capabilities = Capabilities::builder()
            .versions(capabilities.versions().to_vec())
            .ciphersuites(vec![ciphersuite])
            .extensions(capabilities.extensions().to_vec())
            .proposals(capabilities.proposals().to_vec())
            .credentials(credential_types.clone())
            .build();

        self.key_package_bundle = KeyPackage::builder()
            .key_package_extensions(Extensions::default())
            .leaf_node_capabilities(new_capabilities.clone())
            .build(
                ciphersuite,
                &self.core_state.provider,
                &self.signer,
                CredentialWithKey {
                    credential: self.credential_with_key.credential.clone(),
                    signature_key: self.signer.to_public_vec().into(),
                },
            )
            .unwrap();

        // ensure updated correctly
        let updated_capabilities = self
            .key_package_bundle
            .key_package
            .leaf_node()
            .capabilities();

        // Filter out GREASE values for comparison since they're automatically injected
        let filtered_credentials: Vec<_> = updated_capabilities
            .credentials()
            .iter()
            .filter(|cred| !cred.is_grease())
            .copied()
            .collect();
        assert_eq!(filtered_credentials.as_slice(), credential_types);

        // return the updated capabilities
        new_capabilities
    }

    // Helper function to set the CredentialType of the PreGroupPartyState's credential to the
    // specified value (keeping all else equal)
    fn update_credential_type(
        &'a mut self,
        credential_type: CredentialType,
        ciphersuite: Ciphersuite,
    ) {
        // update to a non-supported credential type
        let new_credential = Credential::new(
            credential_type,
            self.credential_with_key
                .credential
                .serialized_content()
                .to_vec(),
        );

        // Update only the new credential
        self.credential_with_key.credential = new_credential.clone();
        // `generate_key_package` leaves capabilities unset, so they'd be
        // derived from the leaf. Here they have to be stated, because the
        // point is to control exactly which credential types the leaf
        // advertises.
        self.key_package_bundle = KeyPackage::builder()
            .key_package_extensions(Extensions::default())
            .leaf_node_capabilities(
                Capabilities::builder()
                    .ciphersuites(vec![ciphersuite])
                    .credentials(vec![credential_type])
                    .build(),
            )
            .build(
                ciphersuite,
                &self.core_state.provider,
                &self.signer,
                CredentialWithKey {
                    credential: new_credential,
                    signature_key: self.signer.to_public_vec().into(),
                },
            )
            .unwrap();
    }
}

// Ensure that this check fails on invalid input:
//   - Test that the credential type is supported by all members of the group,
//     as specified by the capabilities field of each member's leaf node
#[openmls_test::openmls_test]
fn test_valn0104_new_member_unsupported_credential_type() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let dave_party = CorePartyState::<Provider>::new("dave");

    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);

    // assert Bob and Charlie both are initialized to use the Basic credential type
    assert_eq!(
        bob_pre_group
            .credential_with_key
            .credential
            .credential_type(),
        CredentialType::Basic
    );
    assert_eq!(
        charlie_pre_group
            .credential_with_key
            .credential
            .credential_type(),
        CredentialType::Basic
    );

    // Create config
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    // Join config
    let mls_group_join_config = mls_group_create_config.join_config().clone();

    // Initialize the group state
    let group_id = GroupId::from_slice(b"test");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group],
            join_config: mls_group_join_config.clone(),
            tree: None,
        })
        .expect("Could not add member");

    // Should fail with CredentialType::X509
    // Alice adds Dave
    expect_valn0104_error::<Provider>(group_state.add_member_with_credential_type(
        &dave_party,
        "alice",
        ciphersuite,
        CredentialType::X509,
    ));

    // Should fail with CredentialType::Other(3)
    // Alice adds Dave
    expect_valn0104_error::<Provider>(group_state.add_member_with_credential_type(
        &dave_party,
        "alice",
        ciphersuite,
        CredentialType::Other(3),
    ));
    // Should succeed with CredentialType::Basic
    // Alice adds Dave
    group_state
        .add_member_with_credential_type(&dave_party, "alice", ciphersuite, CredentialType::Basic)
        .expect("Should succeed");
}

// Ensure that this check fails on invalid input:
//   - Verify that the capabilities field of the new member's leaf node
//     indicates support for all the credential types currently in use
//     by other members.
#[openmls_test::openmls_test]
fn test_valn0104_new_member_capabilities_not_support_all_credential_types() {
    // Set up Alice with multiple credential capabilities and Other(3) credential
    let alice_party = CorePartyState::<Provider>::new("alice");
    let mut alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let alice_capabilities = alice_pre_group.update_credential_capabilities(
        vec![CredentialType::Basic, CredentialType::Other(3)],
        ciphersuite,
    );
    alice_pre_group.update_credential_type(CredentialType::Other(3), ciphersuite);

    // Set up Bob with multiple credential capabilities and BasicCredential
    let bob_party = CorePartyState::<Provider>::new("bob");
    let mut bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    bob_pre_group.update_credential_capabilities(
        vec![CredentialType::Basic, CredentialType::Other(3)],
        ciphersuite,
    );

    // Set up Charlie with multiple credential capabilities and BasicCredential
    let charlie_party = CorePartyState::<Provider>::new("charlie");
    let mut charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);
    charlie_pre_group.update_credential_capabilities(
        vec![
            CredentialType::Basic,
            CredentialType::Other(3),
            CredentialType::Other(4),
        ],
        ciphersuite,
    );

    let dave_party = CorePartyState::<Provider>::new("dave");
    let eve_party = CorePartyState::<Provider>::new("eve");

    // Create config
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(alice_capabilities)
        .use_ratchet_tree_extension(true)
        .build();

    // Join config
    let mls_group_join_config = mls_group_create_config.join_config().clone();

    // Initialize the group state
    let group_id = GroupId::from_slice(b"test");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();

    // Alice adds Bob and Charlie
    // This should succeed, since all used credential types used are supported
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group],
            join_config: mls_group_join_config.clone(),
            tree: None,
        })
        .expect("Could not add member");

    // Case with only Dave's own credential type (Basic) in his capabilities;
    // should fail because he doesn't support Alice's Other(3) credential.
    // A leaf must list its own credential type, so an empty list can't be
    // tested here; the next case covers insufficient capabilities.
    // Alice adds Dave
    expect_valn0104_error::<Provider>(group_state.add_member_with_credential_capabilities(
        &dave_party,
        "alice",
        ciphersuite,
        vec![CredentialType::Basic],
    ));

    // Case with wrong capabilities; should fail
    // This is because Dave needs to support all the credential types currently in use by other
    // members, which are `Other(3)` (Alice) and `Basic` (Bob, Charlie), but he is missing support for `Other(3)`.
    // Alice adds Dave
    expect_valn0104_error::<Provider>(group_state.add_member_with_credential_capabilities(
        &dave_party,
        "alice",
        ciphersuite,
        vec![CredentialType::Basic, CredentialType::Other(2)],
    ));

    // Case with right capabilities; should succeed
    // Alice adds Dave
    group_state
        .add_member_with_credential_capabilities(
            &dave_party,
            "alice",
            ciphersuite,
            vec![CredentialType::Basic, CredentialType::Other(3)],
        )
        .expect("Should succeed");

    // Case with right capabilities plus more; should succeed
    // Dave adds Eve
    group_state
        .add_member_with_credential_capabilities(
            &eve_party,
            "dave",
            ciphersuite,
            vec![
                CredentialType::Basic,
                CredentialType::Other(3),
                CredentialType::Other(5),
            ],
        )
        .expect("Should succeed");
}

// A member's own new leaf needs to be valid according to valn0104 when it is built.
// Switching to a credential type another member doesn't support is rejected.
#[openmls_test::openmls_test]
fn test_valn0104_own_update_credential_not_supported_by_member() {
    // Alice only supports Basic.
    let alice_party = CorePartyState::<Provider>::new("alice");
    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);

    // Bob supports Basic and Other(3), and uses Basic.
    let bob_party = CorePartyState::<Provider>::new("bob");
    let mut bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    bob_pre_group.update_credential_capabilities(
        vec![CredentialType::Basic, CredentialType::Other(3)],
        ciphersuite,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();
    let mls_group_join_config = mls_group_create_config.join_config().clone();

    let group_id = GroupId::from_slice(b"test");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config: mls_group_join_config,
            tree: None,
        })
        .expect("Could not add member");

    let [bob] = group_state.members_mut(&["bob"]);

    // Same signature key, but a credential type Alice doesn't support.
    let other_credential = CredentialWithKey {
        credential: Credential::new(
            CredentialType::Other(3),
            bob.party
                .credential_with_key
                .credential
                .serialized_content()
                .to_vec(),
        ),
        signature_key: bob.party.credential_with_key.signature_key.clone(),
    };
    let leaf_node_parameters = || {
        LeafNodeParameters::builder()
            .with_credential_with_key(other_credential.clone())
            .build()
    };

    let err = bob
        .group
        .propose_self_update(
            &bob.party.core_state.provider,
            &bob.party.signer,
            leaf_node_parameters(),
        )
        .expect_err("Alice doesn't support Other(3)");
    assert!(
        matches!(
            err,
            ProposeSelfUpdateError::LeafNodeUpdateError(
                crate::treesync::node::leaf_node::LeafNodeUpdateError::Validation(
                    LeafNodeValidationError::LeafNodeCredentialNotSupportedByMember
                )
            )
        ),
        "unexpected error: {err:?}"
    );

    let err = bob
        .build_commit_and_stage(|builder| {
            builder
                .force_self_update(true)
                .leaf_node_parameters(leaf_node_parameters())
        })
        .expect_err("Alice doesn't support Other(3)");
    assert!(
        matches!(
            err,
            GroupError::<Provider>::CreateCommit(CreateCommitError::ApplyOwnUpdatePath(
                ApplyOwnUpdatePathError::LeafNodeBuild(LeafNodeBuildError::Validation(
                    LeafNodeValidationError::LeafNodeCredentialNotSupportedByMember
                ))
            ))
        ),
        "unexpected error: {err:?}"
    );
}

// The other direction of valn0104 for a member's own new leaf: dropping
// support for a credential type another member uses is rejected when the leaf
// is built.
#[openmls_test::openmls_test]
fn test_valn0104_own_update_drops_member_credential() {
    // Alice supports Basic and Other(3), and uses Other(3).
    let alice_party = CorePartyState::<Provider>::new("alice");
    let mut alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let alice_capabilities = alice_pre_group.update_credential_capabilities(
        vec![CredentialType::Basic, CredentialType::Other(3)],
        ciphersuite,
    );
    alice_pre_group.update_credential_type(CredentialType::Other(3), ciphersuite);

    // Bob supports Basic and Other(3), and uses Basic.
    let bob_party = CorePartyState::<Provider>::new("bob");
    let mut bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    bob_pre_group.update_credential_capabilities(
        vec![CredentialType::Basic, CredentialType::Other(3)],
        ciphersuite,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .capabilities(alice_capabilities)
        .use_ratchet_tree_extension(true)
        .build();
    let mls_group_join_config = mls_group_create_config.join_config().clone();

    let group_id = GroupId::from_slice(b"test");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group],
            join_config: mls_group_join_config,
            tree: None,
        })
        .expect("Could not add member");

    let [bob] = group_state.members_mut(&["bob"]);

    // Bob stops advertising Other(3), which Alice uses.
    let leaf_node_parameters = || {
        LeafNodeParameters::builder()
            .with_capabilities(
                Capabilities::builder()
                    .ciphersuites(vec![ciphersuite])
                    .credentials(vec![CredentialType::Basic])
                    .build(),
            )
            .build()
    };

    let err = bob
        .group
        .propose_self_update(
            &bob.party.core_state.provider,
            &bob.party.signer,
            leaf_node_parameters(),
        )
        .expect_err("Bob must keep supporting Alice's Other(3)");
    assert!(
        matches!(
            err,
            ProposeSelfUpdateError::LeafNodeUpdateError(
                crate::treesync::node::leaf_node::LeafNodeUpdateError::Validation(
                    LeafNodeValidationError::MemberCredentialNotSupportedByLeafNode
                )
            )
        ),
        "unexpected error: {err:?}"
    );

    let err = bob
        .build_commit_and_stage(|builder| {
            builder
                .force_self_update(true)
                .leaf_node_parameters(leaf_node_parameters())
        })
        .expect_err("Bob must keep supporting Alice's Other(3)");
    assert!(
        matches!(
            err,
            GroupError::<Provider>::CreateCommit(CreateCommitError::ApplyOwnUpdatePath(
                ApplyOwnUpdatePathError::LeafNodeBuild(LeafNodeBuildError::Validation(
                    LeafNodeValidationError::MemberCredentialNotSupportedByLeafNode
                ))
            ))
        ),
        "unexpected error: {err:?}"
    );
}

// The receiving side of valn0104 for an Update proposal. An honest client
// can't build such a leaf (see the tests above), so the proposal is tampered
// with, and the commit covering it is crafted too, since an honest committer
// would refuse to include it.
#[openmls_test::openmls_test]
fn test_valn0104_incoming_update_credential_not_supported_by_member() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");

    // Only Bob supports Other(3); everyone uses Basic.
    let alice_pre_group = alice_party.generate_pre_group(ciphersuite);
    let mut bob_pre_group = bob_party.generate_pre_group(ciphersuite);
    bob_pre_group.update_credential_capabilities(
        vec![CredentialType::Basic, CredentialType::Other(3)],
        ciphersuite,
    );
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .use_ratchet_tree_extension(true)
        .build();
    let mls_group_join_config = mls_group_create_config.join_config().clone();

    let group_id = GroupId::from_slice(b"test");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();
    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group],
            join_config: mls_group_join_config,
            tree: None,
        })
        .expect("Could not add member");

    let [alice, bob, charlie] = group_state.members_mut(&["alice", "bob", "charlie"]);

    let to_protocol_message = |message: frankenstein::FrankenMlsMessage| {
        MlsMessageIn::tls_deserialize(&mut message.tls_serialize_detached().unwrap().as_slice())
            .unwrap()
            .into_protocol_message()
            .unwrap()
    };

    let (update, _) = bob
        .group
        .propose_self_update(
            &bob.party.core_state.provider,
            &bob.party.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();

    let frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content: mut proposal_content,
                ..
            }),
    } = frankenstein::FrankenMlsMessage::from(update)
    else {
        unreachable!("the group uses plaintext handshake messages")
    };
    let frankenstein::FrankenFramedContent {
        body:
            frankenstein::FrankenFramedContentBody::Proposal(frankenstein::FrankenProposal::Update(
                frankenstein::FrankenUpdateProposal { leaf_node },
            )),
        ..
    } = &mut proposal_content
    else {
        unreachable!("this is an update proposal")
    };

    // Switch Bob's leaf to Other(3). His own capabilities cover it, so the
    // leaf stays self-consistent, but Alice and Charlie don't support it.
    leaf_node.payload.credential = Credential::new(
        CredentialType::Other(3),
        bob.party
            .credential_with_key
            .credential
            .serialized_content()
            .to_vec(),
    )
    .into();
    leaf_node.resign(
        Some(frankenstein::FrankenTreePosition {
            group_id: bob.group.group_id().as_slice().to_vec().into(),
            leaf_index: bob.group.own_leaf_index().u32(),
        }),
        &bob.party.signer,
    );

    let tampered_update = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &bob.party.core_state.provider,
                ciphersuite,
                &bob.party.signer,
                proposal_content.clone(),
                Some(&bob.group.export_group_context().clone().into()),
                Some(bob.group.message_secrets().membership_key().as_slice()),
                None,
            ),
        ),
    };

    // The leaf is only checked against the group once a commit covers the
    // proposal, so Charlie accepts the proposal itself.
    let processed = charlie
        .group
        .process_message(
            &charlie.party.core_state.provider,
            to_protocol_message(tampered_update),
        )
        .expect("proposals aren't checked against the group on receipt");
    let ProcessedMessageContent::ProposalMessage(proposal) = processed.into_content() else {
        panic!("expected a proposal");
    };
    let proposal_ref = proposal.proposal_reference();
    charlie
        .group
        .store_pending_proposal(charlie.party.core_state.provider.storage(), *proposal)
        .unwrap();

    let commit_content = frankenstein::FrankenFramedContent {
        sender: frankenstein::FrankenSender::Member(alice.group.own_leaf_index().u32()),
        body: frankenstein::FrankenFramedContentBody::Commit(frankenstein::FrankenCommit {
            proposals: vec![frankenstein::FrankenProposalOrRef::Reference(
                proposal_ref.as_slice().to_vec().into(),
            )],
            path: None,
        }),
        ..proposal_content
    };
    let commit = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                &alice.party.core_state.provider,
                ciphersuite,
                &alice.party.signer,
                commit_content,
                Some(&alice.group.export_group_context().clone().into()),
                Some(alice.group.message_secrets().membership_key().as_slice()),
                // Proposal validation fails before the tag is checked.
                Some(vec![0; 32].into()),
            ),
        ),
    };

    let err = charlie
        .group
        .process_message(&charlie.party.core_state.provider, to_protocol_message(commit))
        .expect_err("Charlie doesn't support Other(3)");
    // Caught by the ValSem109 capabilities check, which reports any
    // capability mismatch of an Update leaf this way.
    assert!(
        matches!(
            err,
            ProcessMessageError::InvalidCommit(StageCommitError::ProposalValidationError(
                ProposalValidationError::InsufficientCapabilities
            ))
        ),
        "unexpected error: {err:?}"
    );
}

// Ensure that removed members are skipped in the capabilities check
//   - Test that when removing a member from the group, their capabilities are no longer
//     considered when using a new proposal/extension/credential.
#[openmls_test::openmls_test]
fn valn0311_removed_member_capabilities_skipped_in_check() {
    let alice_party = CorePartyState::<Provider>::new("alice");
    let bob_party = CorePartyState::<Provider>::new("bob");
    let charlie_party = CorePartyState::<Provider>::new("charlie");

    let non_default_proposal_id = 0xFFFF;
    let non_default_proposal_type = ProposalType::Custom(non_default_proposal_id);

    // Capabilities that support the non default proposal in addition to the basic ones.
    let capabilities = Capabilities::builder()
        .ciphersuites(vec![ciphersuite])
        .proposals(vec![non_default_proposal_type])
        .credentials(vec![CredentialType::Basic])
        .build();

    // Alice and Bob support the non-default proposal type
    let alice_pre_group = alice_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(capabilities.clone())
        .build();
    let bob_pre_group = bob_party
        .pre_group_builder(ciphersuite)
        .with_leaf_node_capabilities(capabilities.clone())
        .build();

    // Charlie only supports the basic proposal types
    let charlie_pre_group = charlie_party.generate_pre_group(ciphersuite);

    // Negative control: this test only means anything while Charlie does *not*
    // advertise the proposal type. That holds because `minimal_capabilities_for`
    // (the fallback behind `generate_pre_group`) is contractually limited to
    // ciphersuite and credential, and must stay that way.
    assert!(
        !charlie_pre_group
            .key_package_bundle
            .key_package()
            .leaf_node()
            .capabilities()
            .proposals()
            .contains(&non_default_proposal_type),
        "Charlie must not advertise the non-default proposal type"
    );

    // Create config
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .capabilities(capabilities.clone())
        .build();

    // Join config
    let mls_group_join_config = mls_group_create_config.join_config().clone();

    // Initialize the group state
    let group_id = GroupId::from_slice(b"test");
    let mut group_state =
        GroupState::new_from_party(group_id, alice_pre_group, mls_group_create_config).unwrap();

    group_state
        .add_member(AddMemberConfig {
            adder: "alice",
            addees: vec![bob_pre_group, charlie_pre_group],
            join_config: mls_group_join_config.clone(),
            tree: None,
        })
        .expect("Could not add member");

    let non_default_proposal = Proposal::custom(CustomProposal::new(
        non_default_proposal_id,
        vec![0, 1, 2, 3],
    ));

    let mut members = group_state.members_mut(&["alice"]);
    let alice_group_state = members.get_mut(0).unwrap();

    // Remove Charlie and at the same time commit to a proposal that charlie doesn't support
    let commit = alice_group_state
        .build_commit_and_stage(|builder| {
            builder
                .propose_removals(vec![LeafNodeIndex::new(2)])
                .add_proposals(vec![non_default_proposal])
        })
        .unwrap();

    group_state
        .deliver_and_apply_if(commit.into_commit().into(), |member| {
            member.party.core_state.name != "alice"
        })
        .unwrap();
}
