use openmls::{prelude::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::{signatures::Signer, types::SignatureScheme};

const CUSTOM_EXTENSION_TYPE_ID: u16 = 0xff00;
const CUSTOM_EXTENSION_TYPE: ExtensionType = ExtensionType::Unknown(CUSTOM_EXTENSION_TYPE_ID);

#[openmls_test]
/// An example where we add an unknown extension to every commit in the group
/// In this example, the extension we commit is the list of "user names" of the clients in the
/// group.
fn opaque_extension() {
    // ## First we need to set up the clients.
    // Generate credentials with keys
    let (alice_credential, alice_signature_keys) =
        generate_credential("Alice".into(), ciphersuite.signature_algorithm(), provider);

    let (bob_credential, bob_signature_keys) =
        generate_credential("Bob".into(), ciphersuite.signature_algorithm(), provider);

    let (charlie_credential, charlie_signature_keys) = generate_credential(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        provider,
    );

    // Generate Bob's key package so he can be added later.
    // Note that this function also sets the capability for our custom extension type
    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::default(),
        provider,
        &bob_signature_keys,
    );

    let charlie_key_package = generate_key_package(
        ciphersuite,
        charlie_credential.clone(),
        Extensions::default(),
        provider,
        &charlie_signature_keys,
    );

    // ## Next, start setting up the group
    // ANCHOR: mls_group_create_config_example
    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .ciphersuite(ciphersuite)
        // We set two group context extensions here:
        // - the unknown extension
        // - the required capabilities extension, indicating that clients need to support that
        //   extension type (and announce it in their leaf node)
        .with_group_context_extensions(
            Extensions::try_from(vec![
                Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                    &[CUSTOM_EXTENSION_TYPE],
                    &[],
                    &[],
                )),
                Extension::Unknown(
                    CUSTOM_EXTENSION_TYPE_ID,
                    UnknownExtension(br#"["alice"]"#.to_vec()),
                ),
            ])
            .unwrap(),
        )
        .unwrap()
        // we need to specify the non-default extension in alices leaf node's capabilities.
        .capabilities(Capabilities::new(
            None, // Defaults to the group's protocol version
            None, // Defaults to the group's ciphersuite
            Some(&[CUSTOM_EXTENSION_TYPE]),
            None, // Defaults to all basic extension types
            Some(&[CredentialType::Basic]),
        ))
        .build();
    // ANCHOR_END: mls_group_create_config_example

    // ANCHOR: alice_create_group
    let mut alice_group = MlsGroup::new(
        provider,
        &alice_signature_keys,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");
    // ANCHOR_END: alice_create_group

    // ## Build the commit where we add bob:
    // 1. add the client to the group
    // 2. add the name to the list in the required capabilities.
    let add_bob_bundle = alice_group
        .commit_builder()
        .propose_adds(Some(bob_key_package.key_package().clone()))
        .propose_group_context_extensions(
            Extensions::try_from(vec![
                Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                    &[CUSTOM_EXTENSION_TYPE],
                    &[],
                    &[],
                )),
                Extension::Unknown(
                    CUSTOM_EXTENSION_TYPE_ID,
                    UnknownExtension(br#"["alice","bob"]"#.to_vec()),
                ),
            ])
            .unwrap(),
        )
        .load_psks(provider.storage())
        .expect("error loading psks")
        .build(
            provider.rand(),
            provider.crypto(),
            &alice_signature_keys,
            |_| true,
        )
        .expect("error building commit")
        .stage_commit(provider)
        .expect("error staging commit");

    alice_group.merge_pending_commit(provider).unwrap();

    // ## Let bob build the group
    // Get the info needed to build the group - would be part of welcome and group info in the real
    // world
    let join_config = alice_group.configuration();
    let tree = alice_group.export_ratchet_tree();

    // This is how we can access the custom group context extension while joining
    let mut bob_group = StagedWelcome::new_from_welcome(
        provider,
        join_config,
        add_bob_bundle.welcome().unwrap().to_owned(),
        Some(tree.into()),
    )
    .inspect(|staged_welcome| {
        let extension = staged_welcome
            .group_context()
            .extensions()
            .unknown(CUSTOM_EXTENSION_TYPE_ID)
            .unwrap();

        let users: Vec<&str> = serde_json::from_slice(&extension.0).unwrap();
        assert!(users.contains(&"alice"));
        assert!(users.contains(&"bob"));
        assert!(users.len() == 2);
    })
    .unwrap()
    .into_group(provider)
    .unwrap();

    // ## Let Alice add Charlie, so we can see how Bob processes that message
    // The commit is analogous to the one before
    let add_charlie_bundle = alice_group
        .commit_builder()
        .propose_adds(Some(charlie_key_package.key_package().clone()))
        .propose_group_context_extensions(
            Extensions::try_from(vec![
                Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
                    &[CUSTOM_EXTENSION_TYPE],
                    &[],
                    &[],
                )),
                Extension::Unknown(
                    CUSTOM_EXTENSION_TYPE_ID,
                    UnknownExtension(br#"["alice","bob","charlie"]"#.to_vec()),
                ),
            ])
            .unwrap(),
        )
        .load_psks(provider.storage())
        .expect("error loading psks")
        .build(
            provider.rand(),
            provider.crypto(),
            &alice_signature_keys,
            |_| true,
        )
        .expect("error building commit")
        .stage_commit(provider)
        .expect("error staging commit");

    alice_group.merge_pending_commit(provider).unwrap();

    let processed_message = bob_group
        .process_message(
            provider,
            add_charlie_bundle
                .commit()
                .to_owned()
                .into_protocol_message()
                .unwrap(),
        )
        .unwrap();

    match processed_message.into_content() {
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            let extension = commit
                .group_context()
                .extensions()
                .unknown(CUSTOM_EXTENSION_TYPE_ID)
                .unwrap();

            let users: Vec<&str> = serde_json::from_slice(&extension.0).unwrap();
            assert!(users.contains(&"alice"));
            assert!(users.contains(&"bob"));
            assert!(users.contains(&"charlie"));
            assert!(users.len() == 3);

            bob_group.merge_pending_commit(provider).unwrap();
        }
        _ => unreachable!("we know this is a commit"),
    }

    // Now we could also create a group for charlie, but that would look
    // exactly like adding bob, so there is nothing interesting here.
}

fn generate_key_package(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    extensions: Extensions,
    provider: &impl crate::storage::OpenMlsProvider,
    signer: &impl Signer,
) -> KeyPackageBundle {
    // ANCHOR: create_key_package
    // Create the key package
    KeyPackage::builder()
        .leaf_node_capabilities(
            Capabilities::builder()
                .extensions(vec![CUSTOM_EXTENSION_TYPE])
                .build(),
        )
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
    // ANCHOR_END: create_key_package
}

fn generate_credential(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    provider: &impl crate::storage::OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    // ANCHOR: create_basic_credential
    let credential = BasicCredential::new(identity);
    // ANCHOR_END: create_basic_credential
    // ANCHOR: create_credential_keys
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();
    signature_keys.store(provider.storage()).unwrap();
    // ANCHOR_END: create_credential_keys

    (
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signature_keys.to_public_vec().into(),
        },
        signature_keys,
    )
}
