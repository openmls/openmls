use openmls::{
    prelude::{test_utils::new_credential, *},
    storage::OpenMlsProvider,
};

use openmls_test::openmls_test;
use openmls_traits::signatures::Signer;
use tls_codec::{Deserialize, Serialize};

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
        assert!(alice_group.epoch().as_u64() == 0);

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

        assert!(alice_group.epoch().as_u64() == 1);
        assert!(bob_group.epoch() == alice_group.epoch());
        assert!(bob_group.epoch_authenticator() == alice_group.epoch_authenticator());

        // === Alice adds Charlie ===
        let charlie_key_package = generate_key_package(
            ciphersuite,
            Extensions::empty(),
            charlie_provider,
            charlie_credential,
            &charlie_signer,
        );
        let kp_in_proposal = charlie_key_package.clone();

        let (queued_message, _welcome, _group_info) = alice_group
            .add_members(alice_provider, &alice_signer, &[charlie_key_package])
            .unwrap();

        // Alice applies the commit directly
        alice_group.merge_pending_commit(alice_provider).unwrap();

        // Serialize the message.
        let msg_for_bob = queued_message.tls_serialize_detached().unwrap();
        // Bob receives the messages.
        let msg_for_bob = MlsMessageIn::tls_deserialize_exact(msg_for_bob).unwrap();

        // On the message we can get ...
        let wire_format = msg_for_bob.wire_format();

        // ... depending on the type, we can do something ...
        let bob_protocol_message = {
            // Let's get the protocol message ... consumes the msg
            let protocol_message = msg_for_bob.try_into_protocol_message().unwrap();

            // ... this can be a public or a private message
            let wire_format2 = protocol_message.wire_format();
            assert_eq!(wire_format2, wire_format);

            let group_id = protocol_message.group_id();
            assert!(group_id == bob_group.group_id());

            let content_type = protocol_message.content_type();
            assert!(content_type == ContentType::Commit);

            let external = protocol_message.is_external();
            assert!(!external);

            let handshake_msg = protocol_message.is_handshake_message();
            assert!(handshake_msg);

            let epoch = protocol_message.epoch();
            assert_eq!(epoch.as_u64(), 1);

            protocol_message
        };
        // {
        //     // Let's get the message body ... consumes the msg
        //     let body = msg_for_bob.extract();
        // }

        // Inspect the `MlsMessageIn`,
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
            .process_message(bob_provider, bob_protocol_message)
            .expect("Could not process message.");

        // ...could merge pending commits for Alice here...

        // Inspect the staged commit
        if let ProcessedMessageContent::StagedCommitMessage(staged_commit) =
            bob_processed_message.into_content()
        {
            // Confirming that the numbers of proposal types are correct
            assert_eq!(staged_commit.add_proposals().count(), 1);
            assert_eq!(staged_commit.update_proposals().count(), 0);
            assert_eq!(staged_commit.psk_proposals().count(), 0);
            assert_eq!(staged_commit.credentials_to_verify().count(), 2);

            // We can retrieve the key package here, since that's
            // the only member of the `AddProposal` struct.
            for queued_proposal in staged_commit.add_proposals() {
                let add_proposal = queued_proposal.add_proposal();
                let key_package = add_proposal.key_package();

                let signature_key = key_package.leaf_node().signature_key();
                assert_eq!(signature_key, kp_in_proposal.leaf_node().signature_key());
            }

            for credential in staged_commit.credentials_to_verify() {
                // There are two credentials in here that we need to verify.
                // The committer's and the newly added leaf.

                let basic_credential = BasicCredential::try_from(credential.clone()).unwrap();
                let alice = basic_credential.identity() == b"Alice";
                let charlie = basic_credential.identity() == b"Charlie";

                if alice {
                    // This is Alice's new credential. Shouldn't have changed.
                    assert_eq!(
                        &alice_credential.signature_key,
                        staged_commit
                            .update_path_leaf_node()
                            .unwrap()
                            .signature_key()
                    );
                } else if charlie {
                    // This is charlie, so the signature key in the staged commit.
                    // We checked that above already.
                    assert!(basic_credential.identity() == b"Charlie");
                } else {
                    panic!("There should be no other credential");
                }
            }

            // We can also retrieve the signature key from the update path leaf node
            let leaf_node = staged_commit.update_path_leaf_node().unwrap();
            let _signature_key = leaf_node.signature_key();

            // The group context on the staged commit is what it will be if
            // the commit is being applied.
            let new_group_context = staged_commit.group_context();
            assert_eq!(new_group_context.epoch().as_u64(), 2);
            assert_ne!(
                staged_commit.epoch_authenticator().unwrap(),
                bob_group.epoch_authenticator()
            );
            assert_eq!(
                staged_commit.epoch_authenticator().unwrap(),
                alice_group.epoch_authenticator() // Alice already applied the commit.
            );

            // NOTE: `StagedCommit.state` is private. Through this, we would be able to get the
            // `StagedTreeSyncDiff`.
        } else {
            panic!("Expected a StagedCommit.");
        }
    }
}
