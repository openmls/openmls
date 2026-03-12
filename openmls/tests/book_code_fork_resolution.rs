#![cfg(feature = "fork-resolution")]

use openmls::{
    group::{JoinBuilder, ProcessedWelcome},
    prelude::*,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::{signatures::Signer, types::SignatureScheme};

#[openmls_test]
fn book_example_readd() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Generate credentials with keys
    let (alice_credential, alice_signature_keys) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let (bob_credential, bob_signature_keys) = generate_credential(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let (charlie_credential, charlie_signature_keys) = generate_credential(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let bob_kpb = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::empty(),
        bob_provider,
        &bob_signature_keys,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let mls_group_config = mls_group_create_config.join_config();

    // ANCHOR: readd_prepare_group
    // Alice creates a group
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signature_keys,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .unwrap();

    // Alice adds Bob and merges the commit
    let add_bob_messages = alice_group
        .commit_builder()
        .propose_adds(vec![bob_kpb.key_package().clone()])
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signature_keys,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    alice_group.merge_pending_commit(alice_provider).unwrap();

    // Bob joins from the welcome
    let welcome = add_bob_messages.into_welcome().unwrap();
    let mut bob_group =
        StagedWelcome::new_from_welcome(bob_provider, mls_group_config, welcome.clone(), None)
            .unwrap()
            .into_group(bob_provider)
            .unwrap();

    // Now Alice and Bob both add Charlie and merge their own commit.
    // This forks the group.
    let charlie_kpb = generate_key_package(
        ciphersuite,
        charlie_credential,
        Extensions::empty(),
        charlie_provider,
        &charlie_signature_keys,
    );

    let add_charlie_messages = alice_group
        .commit_builder()
        .propose_adds(vec![charlie_kpb.key_package().clone()])
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signature_keys,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    bob_group
        .commit_builder()
        .propose_adds(vec![charlie_kpb.key_package().clone()])
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signature_keys,
            |_| true,
        )
        .unwrap()
        .stage_commit(bob_provider)
        .unwrap();

    alice_group.merge_pending_commit(alice_provider).unwrap();
    bob_group.merge_pending_commit(bob_provider).unwrap();

    // Charlie joins using Alice's invite
    let welcome = add_charlie_messages.into_welcome().unwrap();
    let mut charlie_group =
        StagedWelcome::new_from_welcome(charlie_provider, mls_group_config, welcome, None)
            .unwrap()
            .into_group(charlie_provider)
            .unwrap();

    // We should be forked now, double-check
    // Alice and Charlie are on the same state
    assert_eq!(
        alice_group.confirmation_tag(),
        charlie_group.confirmation_tag()
    );
    // But Bob is different from the other two
    assert_ne!(bob_group.confirmation_tag(), alice_group.confirmation_tag());
    assert_ne!(
        bob_group.confirmation_tag(),
        charlie_group.confirmation_tag()
    );

    // ANCHOR_END: readd_prepare_group

    // ANCHOR: readd_do_it
    // Let Alice re-add the members of the other partition (i.e. Bob)
    let bob_new_kpb = generate_key_package(
        ciphersuite,
        bob_credential,
        Extensions::empty(),
        bob_provider,
        &bob_signature_keys,
    );

    // Alice and Charlie are in the same partition
    let our_partition = &[alice_group.own_leaf_index(), charlie_group.own_leaf_index()];
    let builder = alice_group.recover_fork_by_readding(our_partition).unwrap();

    // Here we iterate over the members of the complement partition to get their key packages.
    // In this example this is trivial, but the pattern extends to more realistic scenarios.
    let readded_key_packages = builder
        .complement_partition()
        .iter()
        .map(|member| {
            let basic_credential = BasicCredential::try_from(member.credential.clone()).unwrap();
            match basic_credential.identity() {
                b"Bob" => bob_new_kpb.key_package().clone(),
                other => panic!(
                    "we only expect bob to be re-added, but found {:?}",
                    String::from_utf8(other.to_vec()).unwrap()
                ),
            }
        })
        .collect();

    // Specify the key packages to be re-added and create the commit
    let readd_messages = builder
        .provide_key_packages(readded_key_packages)
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signature_keys,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    // Make Bob re-join the group and Alice and Charlie merge the commit that adds Bob.
    let (commit, welcome, _) = readd_messages.into_contents();
    let welcome = welcome.unwrap();
    let processed_welcome =
        ProcessedWelcome::new_from_welcome(bob_provider, &mls_group_config, welcome).unwrap();
    let bob_group = JoinBuilder::new(bob_provider, processed_welcome)
        .replace_old_group()
        .build()
        .unwrap()
        .into_group(bob_provider)
        .unwrap();

    alice_group.merge_pending_commit(alice_provider).unwrap();

    if let ProcessedMessageContent::StagedCommitMessage(staged_commit) = charlie_group
        .process_message(charlie_provider, commit.into_protocol_message().unwrap())
        .unwrap()
        .into_content()
    {
        charlie_group
            .merge_staged_commit(charlie_provider, *staged_commit)
            .unwrap()
    } else {
        panic!("expected a commit")
    }

    // The fork should be fixed now, double-check
    assert_eq!(alice_group.confirmation_tag(), bob_group.confirmation_tag());
    assert_eq!(
        alice_group.confirmation_tag(),
        charlie_group.confirmation_tag()
    );
    assert_eq!(
        charlie_group.confirmation_tag(),
        bob_group.confirmation_tag()
    );
    // ANCHOR_END: readd_do_it
}

#[openmls_test]
fn book_example_reboot() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();
    let charlie_provider = &Provider::default();

    // Generate credentials with keys
    let (alice_credential, alice_signature_keys) = generate_credential(
        "Alice".into(),
        ciphersuite.signature_algorithm(),
        alice_provider,
    );

    let (bob_credential, bob_signature_keys) = generate_credential(
        "Bob".into(),
        ciphersuite.signature_algorithm(),
        bob_provider,
    );

    let (charlie_credential, charlie_signature_keys) = generate_credential(
        "Charlie".into(),
        ciphersuite.signature_algorithm(),
        charlie_provider,
    );

    let bob_kpb = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::empty(),
        bob_provider,
        &bob_signature_keys,
    );

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .padding_size(100)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(
            10,   // out_of_order_tolerance
            2000, // maximum_forward_distance
        ))
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        .build();

    let mls_group_config = mls_group_create_config.join_config();

    // ANCHOR: reboot_prepare_group
    // Alice creates a group
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signature_keys,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .unwrap();

    // Alice adds Bob and merges the commit
    let add_bob_messages = alice_group
        .commit_builder()
        .propose_adds(vec![bob_kpb.key_package().clone()])
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signature_keys,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    alice_group.merge_pending_commit(alice_provider).unwrap();

    // Bob joins from the welcome
    let welcome = add_bob_messages.into_welcome().unwrap();
    let mut bob_group =
        StagedWelcome::new_from_welcome(bob_provider, mls_group_config, welcome, None)
            .unwrap()
            .into_group(bob_provider)
            .unwrap();

    // Now Alice and Bob both add Charlie and merge their own commit.
    // This forks the group.
    let charlie_kpb = generate_key_package(
        ciphersuite,
        charlie_credential.clone(),
        Extensions::empty(),
        charlie_provider,
        &charlie_signature_keys,
    );

    let add_charlie_messages = alice_group
        .commit_builder()
        .propose_adds(vec![charlie_kpb.key_package().clone()])
        .load_psks(alice_provider.storage())
        .unwrap()
        .build(
            alice_provider.rand(),
            alice_provider.crypto(),
            &alice_signature_keys,
            |_| true,
        )
        .unwrap()
        .stage_commit(alice_provider)
        .unwrap();

    bob_group
        .commit_builder()
        .propose_adds(vec![charlie_kpb.key_package().clone()])
        .load_psks(bob_provider.storage())
        .unwrap()
        .build(
            bob_provider.rand(),
            bob_provider.crypto(),
            &bob_signature_keys,
            |_| true,
        )
        .unwrap()
        .stage_commit(bob_provider)
        .unwrap();

    alice_group.merge_pending_commit(alice_provider).unwrap();
    bob_group.merge_pending_commit(bob_provider).unwrap();

    // Charlie joins using Alice's invite
    let welcome = add_charlie_messages.into_welcome().unwrap();
    let charlie_group =
        StagedWelcome::new_from_welcome(charlie_provider, mls_group_config, welcome, None)
            .unwrap()
            .into_group(charlie_provider)
            .unwrap();

    // We shoulkd be forked now, double-check
    // Alice and Charlie are on the same state
    assert_eq!(
        alice_group.confirmation_tag(),
        charlie_group.confirmation_tag()
    );
    // But Bob is different from the other two
    assert_ne!(bob_group.confirmation_tag(), alice_group.confirmation_tag());
    assert_ne!(
        bob_group.confirmation_tag(),
        charlie_group.confirmation_tag()
    );
    // ANCHOR_END: reboot_prepare_group

    // ANCHOR: reboot_do_it
    // Let Alice reboot the group. For that she needs new key packages for Bob and Charlie, a;s
    // well as a new group ID.
    let bob_new_kpb = generate_key_package(
        ciphersuite,
        bob_credential,
        Extensions::empty(),
        bob_provider,
        &bob_signature_keys,
    );

    let charlie_new_kpb = generate_key_package(
        ciphersuite,
        charlie_credential,
        Extensions::empty(),
        charlie_provider,
        &charlie_signature_keys,
    );

    let new_group_id: GroupId = GroupId::from_slice(
        alice_group
            .group_id()
            .as_slice()
            .iter()
            .copied()
            .chain(b"-new".iter().copied())
            .collect::<Vec<_>>()
            .as_slice(),
    );

    let (mut alice_group, reboot_messages) = alice_group
        .reboot(new_group_id)
        .finish(
            Extensions::empty(),
            vec![
                bob_new_kpb.key_package().clone(),
                charlie_new_kpb.key_package().clone(),
            ],
            // We can use this closure to add more proposals to the commit builder that is used to
            // create the commit that readds all the other members, but in this case we will leave
            // it as-is.
            |builder| builder,
            alice_provider,
            &alice_signature_keys,
            alice_credential,
        )
        .unwrap();

    alice_group.merge_pending_commit(alice_provider).unwrap();

    // Bob and Charlie join the new group
    let welcome = reboot_messages.into_welcome().unwrap();
    let bob_group =
        StagedWelcome::new_from_welcome(bob_provider, mls_group_config, welcome.clone(), None)
            .unwrap()
            .into_group(bob_provider)
            .unwrap();
    assert_eq!(bob_group.own_leaf_index(), LeafNodeIndex::new(1));

    let charlie_group =
        StagedWelcome::new_from_welcome(charlie_provider, mls_group_config, welcome, None)
            .unwrap()
            .into_group(charlie_provider)
            .unwrap();
    assert_eq!(charlie_group.own_leaf_index(), LeafNodeIndex::new(2));

    // The fork should be fixed now, double-check
    assert_eq!(alice_group.confirmation_tag(), bob_group.confirmation_tag());
    assert_eq!(
        alice_group.confirmation_tag(),
        charlie_group.confirmation_tag()
    );
    assert_eq!(
        bob_group.confirmation_tag(),
        charlie_group.confirmation_tag()
    );
    // ANCHOR_END: reboot_do_it
}

// Everythiong below is copied from book_code.rs

fn generate_credential(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    provider: &impl openmls::storage::OpenMlsProvider,
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

fn generate_key_package(
    ciphersuite: Ciphersuite,
    credential_with_key: CredentialWithKey,
    extensions: Extensions<KeyPackage>,
    provider: &impl openmls::storage::OpenMlsProvider,
    signer: &impl Signer,
) -> KeyPackageBundle {
    // ANCHOR: create_key_package
    // Create the key package
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
    // ANCHOR_END: create_key_package
}
