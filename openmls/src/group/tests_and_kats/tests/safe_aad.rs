//! Integration tests for Safe AAD framing.

use tls_codec::{Deserialize as _, Serialize as _, VLBytes};

use crate::{
    component::{ComponentId, ComponentType, ComponentsList},
    extensions::{
        AppDataDictionary, AppDataDictionaryExtension, Extension, ExtensionType, Extensions,
    },
    framing::*,
    group::{
        tests_and_kats::utils::{generate_credential_with_key, CredentialWithKeyAndSigner},
        *,
    },
    key_packages::{KeyPackage, KeyPackageBundle},
    test_utils::frankenstein,
    treesync::{node::leaf_node::Capabilities, LeafNodeParameters},
};

fn app_data_dictionary_with_safe_aad(required_ids: Vec<ComponentId>) -> Extensions<GroupContext> {
    let mut dictionary = AppDataDictionary::new();
    let safe_aad_id = ComponentId::from(ComponentType::SafeAad);
    let body = ComponentsList::new(required_ids)
        .tls_serialize_detached()
        .expect("serializing ComponentsList must succeed");
    let _ = dictionary.insert(safe_aad_id, body);
    let extension = Extension::AppDataDictionary(AppDataDictionaryExtension::new(dictionary));
    Extensions::single(extension).expect("one app_data_dictionary extension is valid")
}

/// Build a leaf-node capability set advertising `AppDataDictionary` support,
/// which the SafeAAD-enabled groups in these tests require for adds and
/// self-updates to pass the GroupContext-extension capability check.
fn safe_aad_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        None,
        Some(&[ExtensionType::AppDataDictionary]),
        None,
        None,
    )
}

fn key_package_with_app_data_dictionary_support<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    provider: &Provider,
    credential_with_keys: CredentialWithKeyAndSigner,
) -> KeyPackageBundle {
    KeyPackage::builder()
        .leaf_node_capabilities(safe_aad_capabilities())
        .build(
            ciphersuite,
            provider,
            &credential_with_keys.signer,
            credential_with_keys.credential_with_key,
        )
        .expect("building Bob's KeyPackage must succeed")
}

fn create_group_pair<Provider: crate::storage::OpenMlsProvider>(
    ciphersuite: openmls_traits::types::Ciphersuite,
    alice_provider: &Provider,
    bob_provider: &Provider,
    wire_format_policy: WireFormatPolicy,
    safe_aad_required: bool,
) -> (MlsGroup, MlsGroup, CredentialWithKeyAndSigner) {
    let group_id = GroupId::random(alice_provider.rand());

    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );
    let bob_credential = generate_credential_with_key(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let bob_key_package = key_package_with_app_data_dictionary_support(
        ciphersuite,
        bob_provider,
        bob_credential.clone(),
    );

    let builder = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(wire_format_policy)
        .capabilities(safe_aad_capabilities());

    let mls_group_create_config = if safe_aad_required {
        builder
            .with_group_context_extensions(app_data_dictionary_with_safe_aad(vec![]))
            .build()
    } else {
        builder.build()
    };

    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_credential.signer,
        &mls_group_create_config,
        group_id,
        alice_credential.credential_with_key.clone(),
    )
    .expect("creating group");

    let (_commit, welcome_out, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_credential.signer,
            core::slice::from_ref(bob_key_package.key_package()),
        )
        .expect("add member");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("merge pending commit");

    let welcome: MlsMessageIn = welcome_out.into();
    let welcome = welcome.into_welcome().expect("welcome message");
    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("staged welcome")
    .into_group(bob_provider)
    .expect("group from staged welcome");

    (alice_group, bob_group, alice_credential)
}

#[openmls_test::openmls_test]
fn safe_aad_roundtrip_private_message() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (mut alice_group, mut bob_group, alice_credential) = create_group_pair(
        ciphersuite,
        alice_provider,
        bob_provider,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        true,
    );

    assert!(alice_group.context().safe_aad_required());
    assert_eq!(
        alice_group
            .context()
            .safe_aad_required_components()
            .expect("required components must decode"),
        Some(Vec::new())
    );

    let items = vec![
        SafeAadItem::new(0, b"zero".to_vec()),
        SafeAadItem::new(42, b"the answer".to_vec()),
        SafeAadItem::new(u16::MAX, b"max".to_vec()),
    ];
    alice_group.set_safe_aad(items.clone()).unwrap();
    let tail = b"alice-tail".to_vec();
    alice_group.set_aad(tail.clone());

    let msg: MlsMessageIn = alice_group
        .create_message(alice_provider, &alice_credential.signer, b"hello bob")
        .expect("create message")
        .into();

    assert!(alice_group.safe_aad_items().is_empty());
    assert!(alice_group.aad().is_empty());

    let processed = bob_group
        .process_message(bob_provider, msg.into_protocol_message().unwrap())
        .expect("process should succeed");

    let safe_aad = processed.safe_aad().expect("Safe AAD should be present");
    assert_eq!(safe_aad.items(), items.as_slice());
    assert_eq!(processed.tail_aad(), tail.as_slice());
    assert_eq!(processed.safe_aad_item(0), Some(b"zero".as_slice()));
    assert_eq!(processed.safe_aad_item(42), Some(b"the answer".as_slice()));
    assert_eq!(processed.safe_aad_item(u16::MAX), Some(b"max".as_slice()));
    assert_eq!(processed.safe_aad_item(7), None);
    assert!(processed.aad().ends_with(&tail));
    assert!(processed.aad().len() > tail.len());
}

#[openmls_test::openmls_test]
fn safe_aad_roundtrip_public_message_proposal() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (mut alice_group, mut bob_group, alice_credential) = create_group_pair(
        ciphersuite,
        alice_provider,
        bob_provider,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        true,
    );

    let items = vec![SafeAadItem::new(5, b"proposal-aad".to_vec())];
    alice_group.set_safe_aad(items.clone()).unwrap();
    let tail = b"proposal-tail".to_vec();
    alice_group.set_aad(tail.clone());

    let (proposal_out, _proposal_ref) = alice_group
        .propose_self_update(
            alice_provider,
            &alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .expect("propose self update");

    let proposal_in: MlsMessageIn = proposal_out.into();
    let processed = bob_group
        .process_message(bob_provider, proposal_in.into_protocol_message().unwrap())
        .expect("process proposal");

    let safe_aad = processed.safe_aad().expect("Safe AAD present");
    assert_eq!(safe_aad.items(), items.as_slice());
    assert_eq!(processed.tail_aad(), tail.as_slice());
}

#[openmls_test::openmls_test]
fn safe_aad_absent_when_not_required() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (mut alice_group, mut bob_group, alice_credential) = create_group_pair(
        ciphersuite,
        alice_provider,
        bob_provider,
        PURE_CIPHERTEXT_WIRE_FORMAT_POLICY,
        false,
    );

    assert!(!alice_group.context().safe_aad_required());
    assert_eq!(
        alice_group
            .context()
            .safe_aad_required_components()
            .expect("required components must decode"),
        None
    );

    let payload = b"caller-aad-only".to_vec();
    alice_group.set_aad(payload.clone());
    let msg: MlsMessageIn = alice_group
        .create_message(alice_provider, &alice_credential.signer, b"hello")
        .expect("create")
        .into();
    let processed = bob_group
        .process_message(bob_provider, msg.into_protocol_message().unwrap())
        .expect("process");

    assert!(processed.safe_aad().is_none());
    assert_eq!(processed.tail_aad(), payload.as_slice());
    assert_eq!(processed.aad(), payload.as_slice());
}

#[openmls_test::openmls_test]
fn safe_aad_set_rejects_invalid_items() {
    let alice_provider = &Provider::default();
    let group_id = GroupId::random(alice_provider.rand());
    let alice_credential = generate_credential_with_key(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .capabilities(safe_aad_capabilities())
        .with_group_context_extensions(app_data_dictionary_with_safe_aad(vec![]))
        .build();

    let mut alice_group = MlsGroup::new_with_group_id(
        alice_provider,
        &alice_credential.signer,
        &mls_group_create_config,
        group_id,
        alice_credential.credential_with_key.clone(),
    )
    .unwrap();

    let err = alice_group
        .set_safe_aad(vec![
            SafeAadItem::new(5, b"a".to_vec()),
            SafeAadItem::new(2, b"b".to_vec()),
        ])
        .unwrap_err();
    assert_eq!(err, SafeAadError::ItemsNotSortedAscending);

    let err = alice_group
        .set_safe_aad(vec![
            SafeAadItem::new(4, b"a".to_vec()),
            SafeAadItem::new(4, b"b".to_vec()),
        ])
        .unwrap_err();
    assert_eq!(err, SafeAadError::DuplicateComponentId(4));

    assert!(alice_group.safe_aad_items().is_empty());
}

#[openmls_test::openmls_test]
fn safe_aad_rejects_malformed_inbound() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let (mut alice_group, mut bob_group, alice_credential) = create_group_pair(
        ciphersuite,
        alice_provider,
        bob_provider,
        PURE_PLAINTEXT_WIRE_FORMAT_POLICY,
        true,
    );

    let (update_prop, _proposal_ref) = alice_group
        .propose_self_update(
            alice_provider,
            &alice_credential.signer,
            LeafNodeParameters::default(),
        )
        .unwrap();
    // Discard the pending proposal: we won't be sending the original.
    alice_group
        .clear_pending_proposals(alice_provider.storage())
        .unwrap();

    // Decompose the original into its franken form, replace authenticated_data
    // with bytes that can never decode as a SafeAad (a too-large VL prefix),
    // and re-sign so the signature verification does not short-circuit before
    // Safe AAD parsing.
    let frankenstein::FrankenMlsMessage {
        version,
        body:
            frankenstein::FrankenMlsMessageBody::PublicMessage(frankenstein::FrankenPublicMessage {
                content: mut content,
                ..
            }),
    } = frankenstein::FrankenMlsMessage::from(update_prop)
    else {
        panic!("expected public message");
    };

    content.authenticated_data = VLBytes::from(vec![0xffu8, 0xff, 0xff, 0xff]);

    let group_context = alice_group.export_group_context().clone();
    let secrets = alice_group.message_secrets();
    let membership_key = secrets.membership_key().as_slice();

    let franken_message = frankenstein::FrankenMlsMessage {
        version,
        body: frankenstein::FrankenMlsMessageBody::PublicMessage(
            frankenstein::FrankenPublicMessage::auth(
                alice_provider,
                ciphersuite,
                &alice_credential.signer,
                content,
                Some(&group_context.into()),
                Some(membership_key),
                None,
            ),
        ),
    };

    let tampered =
        MlsMessageIn::tls_deserialize_exact(franken_message.tls_serialize_detached().unwrap())
            .unwrap();

    let err = bob_group
        .process_message(bob_provider, tampered.into_protocol_message().unwrap())
        .expect_err("malformed SafeAad must be rejected");

    assert!(
        matches!(err, ProcessMessageError::MalformedSafeAad),
        "unexpected error: {err:#?}"
    );
}
