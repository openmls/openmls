use crate::prelude::*;
use crate::test_utils::single_group_test_framework::*;
use crate::treesync::errors::LeafNodeValidationError;

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
        self.key_package_bundle = generate_key_package(
            ciphersuite,
            CredentialWithKey {
                credential: new_credential,
                signature_key: self.signer.to_public_vec().into(),
            },
            Extensions::default(),
            &self.core_state.provider,
            None,
            &self.signer,
        );
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

    // Case with no credential capabilities; should fail
    // Alice adds Dave
    expect_valn0104_error::<Provider>(group_state.add_member_with_credential_capabilities(
        &dave_party,
        "alice",
        ciphersuite,
        Vec::new(),
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
