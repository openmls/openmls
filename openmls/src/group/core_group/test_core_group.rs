use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    key_store::OpenMlsKeyStore,
    types::{CryptoError, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
use tls_codec::Serialize;

use crate::{
    ciphersuite::{hash_ref::KeyPackageRef, signable::Signable, AeadNonce},
    credentials::*,
    framing::*,
    group::*,
    key_packages::*,
    messages::*,
    schedule::psk::*,
    test_utils::*,
    treesync::{treekem::TreeKemError, TreeSyncError},
};

#[apply(ciphersuites_and_backends)]
fn test_core_group_persistence(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    // Alice creates a group
    let alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    let mut file_out = tempfile::NamedTempFile::new().expect("Could not create file");
    alice_group
        .save(&mut file_out)
        .expect("Could not write group state to file");

    let file_in = file_out
        .reopen()
        .expect("Error re-opening serialized group state file");
    let alice_group_deserialized =
        CoreGroup::load(file_in).expect("Could not deserialize mls group");

    assert_eq!(alice_group, alice_group_deserialized);
}

/// This function flips the last byte of the ciphertext.
pub fn flip_last_byte(ctxt: &mut HpkeCiphertext) {
    let mut last_bits = ctxt
        .ciphertext
        .pop()
        .expect("An unexpected error occurred.");
    last_bits ^= 0xff;
    ctxt.ciphertext.push(last_bits);
}

#[apply(ciphersuites_and_backends)]
fn test_failed_groupinfo_decryption(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    for version in Config::supported_versions() {
        let epoch = GroupEpoch(123);
        let group_id = GroupId::random(backend);
        let tree_hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        let confirmed_transcript_hash = vec![1, 1, 1];
        let extensions = Vec::new();
        let confirmation_tag = ConfirmationTag(Mac {
            mac_value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into(),
        });

        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            backend,
        )
        .expect("An unexpected error occurred.");

        let key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            backend,
            vec![],
        )
        .expect("An unexpected error occurred.");

        let group_info = GroupInfoPayload::new(
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            &Vec::new(),
            &extensions,
            confirmation_tag,
            &KeyPackageRef::new(
                &key_package_bundle
                    .key_package()
                    .tls_serialize_detached()
                    .unwrap(),
                ciphersuite,
                backend.crypto(),
            )
            .unwrap(),
        );

        // Generate key and nonce for the symmetric cipher.
        let welcome_key = AeadKey::random(ciphersuite, backend.rand());
        let welcome_nonce = AeadNonce::random(backend);

        // Generate receiver key pair.
        let receiver_key_pair = backend.crypto().derive_hpke_keypair(
            ciphersuite.hpke_config(),
            Secret::random(ciphersuite, backend, None)
                .expect("Not enough randomness.")
                .as_slice(),
        );
        let hpke_info = b"group info welcome test info";
        let hpke_aad = b"group info welcome test aad";
        let hpke_input = b"these should be the group secrets";
        let mut encrypted_group_secrets = backend.crypto().hpke_seal(
            ciphersuite.hpke_config(),
            receiver_key_pair.public.as_slice(),
            hpke_info,
            hpke_aad,
            hpke_input,
        );

        let group_info = group_info
            .sign(backend, &alice_credential_bundle)
            .expect("Error signing group info");

        // Mess with the ciphertext by flipping the last byte.
        flip_last_byte(&mut encrypted_group_secrets);

        let broken_secrets = vec![EncryptedGroupSecrets {
            key_package_hash: key_package_bundle
                .key_package
                .hash(backend)
                .expect("Could not hash KeyPackage.")
                .into(),
            encrypted_group_secrets,
        }];

        // Encrypt the group info.
        let encrypted_group_info = welcome_key
            .aead_seal(
                backend,
                &group_info
                    .tls_serialize_detached()
                    .expect("An unexpected error occurred."),
                &[],
                &welcome_nonce,
            )
            .expect("An unexpected error occurred.");

        // Now build the welcome message.
        let broken_welcome = Welcome::new(
            *version,
            ciphersuite,
            broken_secrets,
            encrypted_group_info.clone(),
        );

        let error = CoreGroup::new_from_welcome(broken_welcome, None, key_package_bundle, backend)
            .expect_err("Creation of core group from a broken Welcome was successful.");

        assert_eq!(
            error,
            WelcomeError::CryptoError(CryptoError::HpkeDecryptionError)
        )
    }
}

/// Test what happens if the KEM ciphertext for the receiver in the UpdatePath
/// is broken.
#[apply(ciphersuites_and_backends)]
fn test_update_path(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group ===
    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");
    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path());
    // Check that the function returned a Welcome message
    assert!(create_commit_result.welcome_option.is_some());

    println!(
        " *** Confirmation tag: {:?}",
        create_commit_result.commit.confirmation_tag()
    );

    alice_group
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging pending commit");
    let ratchet_tree = alice_group.treesync().export_nodes();

    let group_bob = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        backend,
    )
    .expect("An unexpected error occurred.");

    // === Bob updates and commits ===
    let bob_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
            backend,
        )
        .expect("Could not create proposal.");
    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_bob)
            .expect("Could not create QueuedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&bob_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_bob
        .create_commit(params, backend)
        .expect("An unexpected error occurred.");

    // Now we break Alice's HPKE ciphertext in Bob's commit by breaking
    // apart the commit, manipulating the ciphertexts and the piecing it
    // back together.
    let commit = match create_commit_result.commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Bob created a commit, which does not contain an actual commit."),
    };

    let commit = commit.clone();

    let path = commit.path.expect("An unexpected error occurred.");

    let mut broken_path = path;
    // For simplicity, let's just break all the ciphertexts.
    broken_path.flip_eps_bytes();

    // Now let's create a new commit from out broken update path.
    let broken_commit = Commit {
        proposals: commit.proposals,
        path: Some(broken_path),
    };

    let sender = Sender::build_member(
        create_commit_result
            .commit
            .sender()
            .as_key_package_ref()
            .unwrap(),
    );
    let mut broken_plaintext = MlsPlaintext::commit(
        framing_parameters,
        sender,
        broken_commit,
        &bob_credential_bundle,
        group_bob.context(),
        backend,
    )
    .expect("Could not create plaintext.");

    broken_plaintext.set_confirmation_tag(
        create_commit_result
            .commit
            .confirmation_tag()
            .cloned()
            .expect("An unexpected error occurred."),
    );

    println!(
        "Confirmation tag: {:?}",
        broken_plaintext.confirmation_tag()
    );

    let serialized_context = &group_bob
        .group_context
        .tls_serialize_detached()
        .expect("An unexpected error occurred.") as &[u8];

    broken_plaintext
        .set_membership_tag(
            backend,
            serialized_context,
            group_bob.message_secrets().membership_key(),
        )
        .expect("Could not add membership key");

    let staged_commit_res =
        alice_group.stage_commit(&broken_plaintext, &proposal_store, &[], backend);
    assert_eq!(
        staged_commit_res.expect_err("Successful processing of a broken commit."),
        CoreGroupError::TreeKemError(TreeKemError::PathSecretError(
            PathSecretError::DecryptionError(CryptoError::HpkeDecryptionError)
        ))
    );
}

// Test several scenarios when PSKs are used in a group
#[apply(ciphersuites_and_backends)]
fn test_psks(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group with a PSK ===
    let psk_id = vec![1u8, 2, 3];

    let secret = Secret::random(ciphersuite, backend, None /* MLS version */)
        .expect("Not enough randomness.");
    let external_psk = ExternalPsk::new(psk_id);
    let preshared_key_id =
        PreSharedKeyId::new(ciphersuite, backend.rand(), Psk::External(external_psk))
            .expect("An unexpected error occured.");
    let psk_bundle = PskBundle::new(secret).expect("Could not create PskBundle.");
    backend
        .key_store()
        .store(&preshared_key_id, &psk_bundle)
        .expect("An unexpected error occured.");
    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_psk(vec![preshared_key_id.clone()])
        .build(backend)
        .expect("Error creating group.");

    // === Alice creates a PSK proposal ===
    log::info!(" >>> Creating psk proposal ...");
    let psk_proposal = alice_group
        .create_presharedkey_proposal(
            framing_parameters,
            &alice_credential_bundle,
            preshared_key_id,
            backend,
        )
        .expect("Could not create PSK proposal");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );
    proposal_store.add(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, psk_proposal)
            .expect("Could not create QueuedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    alice_group
        .merge_commit(create_commit_result.staged_commit)
        .expect("error merging pending commit");
    let ratchet_tree = alice_group.treesync().export_nodes();

    let group_bob = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        backend,
    )
    .expect("Could not create new group from Welcome");

    // === Bob updates and commits ===
    let bob_update_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
            backend,
        )
        .expect("Could not create proposal.");
    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_bob)
            .expect("Could not create QueuedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&bob_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let _create_commit_result = group_bob
        .create_commit(params, backend)
        .expect("An unexpected error occurred.");
}

// Test several scenarios when PSKs are used in a group
#[apply(ciphersuites_and_backends)]
fn test_staged_commit_creation(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let bob_credential_bundle = CredentialBundle::new(
        "Bob".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    let bob_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &bob_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");
    let bob_key_package = bob_key_package_bundle.key_package();

    // === Alice creates a group ===
    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            &alice_credential_bundle,
            bob_key_package.clone(),
            backend,
        )
        .expect("Could not create proposal.");
    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    // === Alice merges her own commit ===
    alice_group
        .merge_commit(create_commit_result.staged_commit)
        .expect("error processing own staged commit");

    // === Bob joins the group using Alice's tree ===
    let group_bob = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(alice_group.treesync().export_nodes()),
        bob_key_package_bundle,
        backend,
    )
    .expect("An unexpected error occurred.");

    // Let's make sure we end up in the same group state.
    assert_eq!(
        group_bob.export_secret(backend, "", b"test", ciphersuite.hash_length()),
        alice_group.export_secret(backend, "", b"test", ciphersuite.hash_length())
    );
    assert_eq!(
        group_bob.treesync().export_nodes(),
        alice_group.treesync().export_nodes()
    )
}

// Test processing of own commits
#[apply(ciphersuites_and_backends)]
fn test_own_commit_processing(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    // Define credential bundles
    let alice_credential_bundle = CredentialBundle::new(
        "Alice".into(),
        CredentialType::Basic,
        ciphersuite.signature_scheme(),
        backend,
    )
    .expect("An unexpected error occurred.");

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &[ciphersuite.name()],
        &alice_credential_bundle,
        backend,
        Vec::new(),
    )
    .expect("An unexpected error occurred.");

    // === Alice creates a group ===
    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .build(backend)
        .expect("Error creating group.");

    let proposal_store = ProposalStore::default();
    // Alice creates a commit
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(true)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend)
        .expect("error creating commit");

    // Alice attempts to process her own commit
    let error = alice_group
        .stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect_err("no error while processing own commit");
    assert_eq!(
        error,
        CoreGroupError::TreeSyncError(TreeSyncError::LeafNotInTree)
    );
}
