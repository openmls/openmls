use openmls::{
    prelude::{test_utils::new_credential, *},
    storage::OpenMlsProvider,
};

use openmls_test::openmls_test;
use openmls_traits::signatures::Signer;

fn generate_key_package<Provider: OpenMlsProvider>(
    ciphersuite: Ciphersuite,
    extensions: Extensions,
    provider: &Provider,
    credential_with_key: CredentialWithKey,
    signer: &impl Signer,
) -> KeyPackage {
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
        .key_package()
        .clone()
}

/// This test describes a scenario in which, in a group with two members,
///  the first member adds a third, new member. The second member then
///  inspects the staged commit before committing.
///  - Alice creates a group
///  - Alice adds Bob
///  - Alice adds Charlie
///  - Bob inspects the add commit
#[openmls_test]
fn mls_test_inspect_add_commit() {
    for wire_format_policy in [
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
    ] {
        let group_id = GroupId::from_slice(b"Test Group");

        let alice_provider = &Provider::default();
        let bob_provider = &Provider::default();
        let charlie_provider = &Provider::default();

        // Generate credentials with keys
        let (alice_credential, alice_signer) =
            new_credential(alice_provider, b"Alice", ciphersuite.signature_algorithm());

        let (bob_credential, bob_signer) =
            new_credential(bob_provider, b"Bob", ciphersuite.signature_algorithm());

        let (charlie_credential, charlie_signer) = new_credential(
            charlie_provider,
            b"Charlie",
            ciphersuite.signature_algorithm(),
        );

        // Generate KeyPackages
        let bob_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            bob_provider,
            bob_credential.clone(),
            &bob_signer,
        );

        // Define the MlsGroup configuration

        let mls_group_create_config = MlsGroupCreateConfig::builder()
            .wire_format_policy(wire_format_policy)
            .ciphersuite(ciphersuite)
            .build();

        // === Alice creates a group ===
        let mut alice_group = MlsGroup::new_with_group_id(
            alice_provider,
            &alice_signer,
            &mls_group_create_config,
            group_id.clone(),
            alice_credential.clone(),
        )
        .expect("An unexpected error occurred.");

        // === Alice adds Bob ===
        let welcome =
            match alice_group.add_members(alice_provider, &alice_signer, &[bob_key_package]) {
                Ok((_, welcome, _)) => welcome,
                Err(e) => panic!("Could not add member to group: {e:?}"),
            };

        alice_group
            .merge_pending_commit(alice_provider)
            .expect("error merging pending commit");

        let welcome: MlsMessageIn = welcome.into();
        let welcome = welcome
            .into_welcome()
            .expect("expected the message to be a welcome message");

        let mut bob_group = StagedWelcome::new_from_welcome(
            bob_provider,
            mls_group_create_config.join_config(),
            welcome,
            Some(alice_group.export_ratchet_tree().into()),
        )
        .expect("Error creating StagedWelcome from Welcome")
        .into_group(bob_provider)
        .expect("Error creating group from StagedWelcome");

        // === Alice adds Charlie ===
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            charlie_provider,
            charlie_credential,
            &charlie_signer,
        );

        let (queued_message, _welcome, _group_info) = alice_group
            .add_members(alice_provider, &alice_signer, &[charlie_key_package])
            .unwrap();

        // Inspect the `MlsMessageBodyOut` in the `MlsMessageOut`,
        // which is the only thing we can retrieve from it via the public API
        if wire_format_policy == PURE_PLAINTEXT_WIRE_FORMAT_POLICY {
            if let MlsMessageBodyOut::PublicMessage(public_message) = queued_message.body() {
                // NOTE: `public_message.content` is private. This would be
                // another way to access a `FramedContentBody::Commit(Commit)`,
                // which also provides access to `Proposal`s.
                // However, those doesn't provide any information beyond what we can get
                // from the `StagedCommit`.

                // We can retrieve the `ContentType` here, but nothing else from the public API
                assert_eq!(public_message.content_type(), ContentType::Commit);
            } else {
                panic!("Expected public message");
            }
        } else if wire_format_policy == PURE_CIPHERTEXT_WIRE_FORMAT_POLICY {
            if let MlsMessageBodyOut::PrivateMessage(_private_message) = queued_message.body() {
                // NOTE: There's nothing we can retrieve from the private message
                // via the public API.
            } else {
                panic!("Expected private message");
            }
        }

        // Now, get the processed message for Bob
        let bob_processed_message = bob_group
            .process_message(
                bob_provider,
                queued_message
                    .clone()
                    .into_protocol_message()
                    .expect("Unexpected message type"),
            )
            .expect("Could not process message.");

        // ...could merge pending commits for Alice here...

        // Inspect the staged commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            // We can retrieve the key package here, since that's
            // the only member of the `AddProposal` struct.
            for queued_proposal in staged_commit.add_proposals() {
                let add_proposal = queued_proposal.add_proposal();
                let _key_package = add_proposal.key_package();
            }

            // Confirming that the numbers of other proposal types are correct
            assert_eq!(staged_commit.add_proposals().count(), 1);
            assert_eq!(staged_commit.update_proposals().count(), 0);
            assert_eq!(staged_commit.psk_proposals().count(), 0);

            // We can also retrieve the signature key from the update path leaf node
            let leaf_node = staged_commit.update_path_leaf_node().unwrap();
            let _signature_key = leaf_node.signature_key();

            // NOTE: `StagedCommit.state` is private. Through this, we would be able to get the
            // `StagedTreeSyncDiff`.
        } else {
            panic!("Expected a StagedCommit.");
        }
    }
}
