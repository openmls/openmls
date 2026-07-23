//! Runnable, anchor-tagged example for the "Sub-group branching" book chapter.
//!
//! Keep the anchors in sync with `book/src/user_manual/sub-groups.md`.

use openmls::{group::BranchInfo, prelude::*};
use openmls_basic_credential::SignatureKeyPair;
use openmls_test::openmls_test;
use openmls_traits::{signatures::Signer, types::SignatureScheme};

#[openmls_test]
fn book_example_sub_group_branching() {
    let alice_provider = &Provider::default();
    let bob_provider = &Provider::default();

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

    let mls_group_create_config = MlsGroupCreateConfig::builder()
        .ciphersuite(ciphersuite)
        .use_ratchet_tree_extension(true)
        // Sub-group branching relies on resumption PSKs, so make sure the group
        // keeps enough of them around.
        .number_of_resumption_psks(5)
        .build();

    // ANCHOR: parent_group_setup
    // Alice creates the parent group and adds Bob to it.
    let mut alice_group = MlsGroup::new(
        alice_provider,
        &alice_signature_keys,
        &mls_group_create_config,
        alice_credential.clone(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package = generate_key_package(
        ciphersuite,
        bob_credential.clone(),
        Extensions::empty(),
        bob_provider,
        &bob_signature_keys,
    );

    let (_commit, welcome, _group_info) = alice_group
        .add_members(
            alice_provider,
            &alice_signature_keys,
            &[bob_key_package.key_package().clone()],
        )
        .expect("Could not add Bob to the group.");
    alice_group
        .merge_pending_commit(alice_provider)
        .expect("Could not merge commit.");

    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("Expected the message to be a welcome message.");

    let bob_group = StagedWelcome::new_from_welcome(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error constructing staged welcome.")
    .into_group(bob_provider)
    .expect("Error joining the group.");
    // ANCHOR_END: parent_group_setup

    // ANCHOR: export_branch_info
    // Both sides export the information the branch needs from the parent group.
    let alice_branch_info: BranchInfo = alice_group.branch_info();
    let bob_branch_info: BranchInfo = bob_group.branch_info();
    // ANCHOR_END: export_branch_info

    let bob_sub_key_package = generate_key_package(
        ciphersuite,
        bob_credential,
        Extensions::empty(),
        bob_provider,
        &bob_signature_keys,
    );

    // ANCHOR: sender_branch
    // Creating the sub-group and its branch commit is a single builder
    // operation. The sub-group uses the parent's ciphersuite automatically; set
    // any other group configuration on the builder before calling `branch`.
    let (mut alice_sub_group, commit_message_bundle) = MlsGroup::builder()
        .use_ratchet_tree_extension(true)
        .number_of_resumption_psks(5)
        .branch(alice_branch_info)
        .build_branch(
            alice_provider,
            &alice_signature_keys,
            alice_credential,
            vec![bob_sub_key_package.key_package().clone()],
        )
        .expect("Could not create the sub-group branch.");

    // The commit is staged but not merged yet.
    alice_sub_group
        .merge_pending_commit(alice_provider)
        .expect("Could not merge commit.");

    let welcome = commit_message_bundle
        .welcome()
        .expect("An unexpected error occurred.")
        .clone();
    // ANCHOR_END: sender_branch

    let welcome = MlsMessageOut::from_welcome(welcome, ProtocolVersion::Mls10);
    let welcome: MlsMessageIn = welcome.into();
    let welcome = welcome
        .into_welcome()
        .expect("Expected the message to be a welcome message.");
    let sub_group_ratchet_tree = alice_sub_group.export_ratchet_tree();

    // ANCHOR: receiver_join_branch
    // Bob joins the sub-group with the builder returned by `build_from_branch`,
    // passing his own view of the parent group as `BranchInfo`. `build_from_branch`
    // checks that the branch PSK references the same parent group/epoch as the
    // `BranchInfo`; the remaining receiver checks (matching version, ciphersuite,
    // sub-group epoch, and membership) run when `build` is called.
    let bob_sub_group = StagedWelcome::build_from_branch(
        bob_provider,
        mls_group_create_config.join_config(),
        welcome,
        bob_branch_info,
    )
    .expect("Error processing the branch welcome.")
    .with_ratchet_tree(sub_group_ratchet_tree.into())
    // .check_members(false) // optional; the membership check is on by default
    .build()
    .expect("Error joining the sub-group.")
    .into_group(bob_provider)
    .expect("Error creating the sub-group.");
    // ANCHOR_END: receiver_join_branch

    // ANCHOR: verify
    // Both sides derived the same sub-group state.
    assert_eq!(
        alice_sub_group.confirmation_tag(),
        bob_sub_group.confirmation_tag()
    );
    // ANCHOR_END: verify
}

fn generate_credential(
    identity: Vec<u8>,
    signature_algorithm: SignatureScheme,
    provider: &impl openmls::storage::OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(identity);
    let signature_keys = SignatureKeyPair::new(signature_algorithm).unwrap();
    signature_keys.store(provider.storage()).unwrap();

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
    KeyPackage::builder()
        .key_package_extensions(extensions)
        .build(ciphersuite, provider, signer, credential_with_key)
        .unwrap()
}
