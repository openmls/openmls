use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, types::HpkeCiphertext, OpenMlsCryptoProvider};
use tls_codec::Serialize;

use crate::{
    binary_tree::*,
    ciphersuite::{signable::Signable, AeadNonce},
    credentials::*,
    framing::*,
    group::{config::CryptoConfig, errors::*, *},
    key_packages::*,
    messages::{group_info::GroupInfoTBS, *},
    schedule::psk::{store::ResumptionPskStore, ExternalPsk, PreSharedKeyId, Psk},
    test_utils::*,
    treesync::{errors::ApplyUpdatePathError, node::leaf_node::TreeInfoTbs},
};

pub(crate) fn setup_alice_group(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (
    CoreGroup,
    CredentialWithKey,
    SignatureKeyPair,
    OpenMlsSignaturePublicKey,
) {
    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) = test_utils::new_credential(
        backend,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let pk = OpenMlsSignaturePublicKey::new(
        alice_signature_keys.to_public_vec().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

    // Alice creates a group
    let group = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key.clone(),
    )
    .build(backend, &alice_signature_keys)
    .expect("Error creating group.");
    (group, alice_credential_with_key, alice_signature_keys, pk)
}

#[apply(ciphersuites_and_backends)]
fn test_core_group_persistence(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    let (alice_group, _, _, _) = setup_alice_group(ciphersuite, backend);

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
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    let epoch = 123;
    let group_id = GroupId::random(backend);
    let tree_hash = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
    let confirmed_transcript_hash = vec![1, 1, 1];
    let extensions = Extensions::empty();
    let confirmation_tag = ConfirmationTag(Mac {
        mac_value: vec![1, 2, 3, 4, 5, 6, 7, 8, 9].into(),
    });

    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) = test_utils::new_credential(
        backend,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    let key_package_bundle = KeyPackageBundle::new(
        backend,
        &alice_signature_keys,
        ciphersuite,
        alice_credential_with_key,
    );

    let group_info_tbs = {
        let group_context = GroupContext::new(
            ciphersuite,
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            Extensions::empty(),
        );

        GroupInfoTBS::new(
            group_context,
            extensions,
            confirmation_tag,
            LeafNodeIndex::new(0),
        )
    };

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
    let hpke_context = b"group info welcome test info";
    let group_secrets = b"these should be the group secrets";
    let mut encrypted_group_secrets = hpke::encrypt_with_label(
        receiver_key_pair.public.as_slice(),
        "Welcome",
        hpke_context,
        group_secrets,
        ciphersuite,
        backend.crypto(),
    )
    .unwrap();

    let group_info = group_info_tbs
        .sign(&alice_signature_keys)
        .expect("Error signing group info");

    // Mess with the ciphertext by flipping the last byte.
    flip_last_byte(&mut encrypted_group_secrets);

    let broken_secrets = vec![EncryptedGroupSecrets::new(
        key_package_bundle
            .key_package
            .hash_ref(backend.crypto())
            .expect("Could not hash KeyPackage."),
        encrypted_group_secrets,
    )];

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
    let broken_welcome = Welcome::new(ciphersuite, broken_secrets, encrypted_group_info);

    let error = CoreGroup::new_from_welcome(
        broken_welcome,
        None,
        key_package_bundle,
        backend,
        ResumptionPskStore::new(1024),
    )
    .expect_err("Creation of core group from a broken Welcome was successful.");

    assert_eq!(
        error,
        WelcomeError::GroupSecrets(GroupSecretsError::DecryptionFailed)
    )
}

/// Test what happens if the KEM ciphertext for the receiver in the UpdatePath
/// is broken.
#[apply(ciphersuites_and_backends)]
fn test_update_path(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // === Alice creates a group with her and Bob ===
    let (
        framing_parameters,
        group_alice,
        _alice_signature_keys,
        group_bob,
        bob_signature_keys,
        _bob_credential_with_key,
    ) = test_framing::setup_alice_bob_group(ciphersuite, backend);

    // === Bob updates and commits ===
    let bob_old_leaf = group_bob.own_leaf_node().unwrap();
    let bob_update_leaf_node = bob_old_leaf
        .updated(
            CryptoConfig::with_default_version(ciphersuite),
            TreeInfoTbs::Update(group_bob.own_tree_position()),
            backend,
            &bob_signature_keys,
        )
        .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            bob_update_leaf_node,
            &bob_signature_keys,
        )
        .expect("Could not create proposal.");
    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            backend,
            update_proposal_bob,
        )
        .expect("Could not create QueuedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = group_bob
        .create_commit(params, backend, &bob_signature_keys)
        .expect("An unexpected error occurred.");

    // Now we break Alice's HPKE ciphertext in Bob's commit by breaking
    // apart the commit, manipulating the ciphertexts and the piecing it
    // back together.
    let commit = match create_commit_result.commit.content() {
        FramedContentBody::Commit(commit) => commit,
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

    let mut broken_plaintext = AuthenticatedContent::commit(
        framing_parameters,
        create_commit_result.commit.sender().clone(),
        broken_commit,
        group_bob.context(),
        &bob_signature_keys,
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

    let staged_commit_res =
        group_alice.read_keys_and_stage_commit(&broken_plaintext, &proposal_store, &[], backend);
    assert_eq!(
        staged_commit_res.expect_err("Successful processing of a broken commit."),
        StageCommitError::UpdatePathError(ApplyUpdatePathError::UnableToDecrypt)
    );
}

fn setup_alice_bob(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (
    CredentialWithKey,
    SignatureKeyPair,
    KeyPackageBundle,
    SignatureKeyPair,
) {
    // Create credentials and keys
    let (alice_credential_with_key, alice_signer) = test_utils::new_credential(
        backend,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let (bob_credential_with_key, bob_signer) = test_utils::new_credential(
        backend,
        b"Bob",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    // Generate Bob's KeyPackage
    let bob_key_package_bundle =
        KeyPackageBundle::new(backend, &bob_signer, ciphersuite, bob_credential_with_key);

    (
        alice_credential_with_key,
        alice_signer,
        bob_key_package_bundle,
        bob_signer,
    )
}

// Test several scenarios when PSKs are used in a group
#[apply(ciphersuites_and_backends)]
fn test_psks(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    let (
        alice_credential_with_key,
        alice_signature_keys,
        bob_key_package_bundle,
        bob_signature_keys,
    ) = setup_alice_bob(ciphersuite, backend);

    // === Alice creates a group with a PSK ===
    let psk_id = vec![1u8, 2, 3];

    let secret = Secret::random(ciphersuite, backend, None /* MLS version */)
        .expect("Not enough randomness.");
    let external_psk = ExternalPsk::new(psk_id);
    let preshared_key_id =
        PreSharedKeyId::new(ciphersuite, backend.rand(), Psk::External(external_psk))
            .expect("An unexpected error occured.");
    preshared_key_id
        .write_to_key_store(backend, ciphersuite, secret.as_slice())
        .unwrap();
    let mut alice_group = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key,
    )
    .with_psk(vec![preshared_key_id.clone()])
    .build(backend, &alice_signature_keys)
    .expect("Error creating group.");

    // === Alice creates a PSK proposal ===
    log::info!(" >>> Creating psk proposal ...");
    let psk_proposal = alice_group
        .create_presharedkey_proposal(framing_parameters, preshared_key_id, &alice_signature_keys)
        .expect("Could not create PSK proposal");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            bob_key_package_bundle.key_package().clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal");

    let mut proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );
    proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(ciphersuite, backend, psk_proposal)
            .expect("Could not create QueuedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    alice_group
        .merge_commit(backend, create_commit_result.staged_commit)
        .expect("error merging pending commit");
    let ratchet_tree = alice_group.public_group().export_ratchet_tree();

    let group_bob = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_key_package_bundle,
        backend,
        ResumptionPskStore::new(1024),
    )
    .expect("Could not create new group from Welcome");

    // === Bob updates and commits ===
    let bob_old_leaf = group_bob.own_leaf_node().unwrap();
    let bob_update_leaf_node = bob_old_leaf
        .updated(
            CryptoConfig::with_default_version(ciphersuite),
            TreeInfoTbs::Update(group_bob.own_tree_position()),
            backend,
            &bob_signature_keys,
        )
        .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
            framing_parameters,
            bob_update_leaf_node,
            &bob_signature_keys,
        )
        .expect("Could not create proposal.");
    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            backend,
            update_proposal_bob,
        )
        .expect("Could not create QueuedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let _create_commit_result = group_bob
        .create_commit(params, backend, &bob_signature_keys)
        .expect("An unexpected error occurred.");
}

// Test several scenarios when PSKs are used in a group
#[apply(ciphersuites_and_backends)]
fn test_staged_commit_creation(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    let (alice_credential_with_key, alice_signature_keys, bob_key_package_bundle, _) =
        setup_alice_bob(ciphersuite, backend);

    // === Alice creates a group ===
    let mut alice_group = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key,
    )
    .build(backend, &alice_signature_keys)
    .expect("Error creating group.");

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            bob_key_package_bundle.key_package().clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal.");
    let proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating commit");

    // === Alice merges her own commit ===
    alice_group
        .merge_commit(backend, create_commit_result.staged_commit)
        .expect("error processing own staged commit");

    // === Bob joins the group using Alice's tree ===
    let group_bob = CoreGroup::new_from_welcome(
        create_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(alice_group.public_group().export_ratchet_tree().into()),
        bob_key_package_bundle,
        backend,
        ResumptionPskStore::new(1024),
    )
    .expect("An unexpected error occurred.");

    // Let's make sure we end up in the same group state.
    assert_eq!(
        group_bob.export_secret(backend, "", b"test", ciphersuite.hash_length()),
        alice_group.export_secret(backend, "", b"test", ciphersuite.hash_length())
    );
    assert_eq!(
        group_bob.public_group().export_ratchet_tree(),
        alice_group.public_group().export_ratchet_tree()
    )
}

// Test processing of own commits
#[apply(ciphersuites_and_backends)]
fn test_own_commit_processing(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    // Create credentials and keys
    let (alice_credential_with_key, alice_signature_keys) = test_utils::new_credential(
        backend,
        b"Alice",
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );

    // === Alice creates a group ===
    let alice_group = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key,
    )
    .build(backend, &alice_signature_keys)
    .expect("Error creating group.");

    let proposal_store = ProposalStore::default();
    // Alice creates a commit
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&proposal_store)
        .force_self_update(true)
        .build();
    let create_commit_result = alice_group
        .create_commit(params, backend, &alice_signature_keys)
        .expect("error creating commit");

    // Alice attempts to process her own commit
    let error = alice_group
        .read_keys_and_stage_commit(&create_commit_result.commit, &proposal_store, &[], backend)
        .expect_err("no error while processing own commit");
    assert_eq!(error, StageCommitError::OwnCommit);
}

pub(crate) fn setup_client(
    id: &str,
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) -> (
    CredentialWithKey,
    KeyPackageBundle,
    SignatureKeyPair,
    OpenMlsSignaturePublicKey,
) {
    let (credential_with_key, signature_keys) = test_utils::new_credential(
        backend,
        id.as_bytes(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
    );
    let pk = OpenMlsSignaturePublicKey::new(
        signature_keys.to_public_vec().into(),
        ciphersuite.signature_algorithm(),
    )
    .unwrap();

    // Generate the KeyPackage
    let key_package_bundle = KeyPackageBundle::new(
        backend,
        &signature_keys,
        ciphersuite,
        credential_with_key.clone(),
    );
    (credential_with_key, key_package_bundle, signature_keys, pk)
}

#[apply(ciphersuites_and_backends)]
fn test_proposal_application_after_self_was_removed(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // We're going to test if proposals are still applied, even after a client
    // notices that it was removed from a group.  We do so by having Alice
    // create a group, add Bob and then create a commit where Bob is removed and
    // Charlie is added in a single commit (by Alice). We then check if
    // everyone's membership list is as expected.

    // Basic group setup.
    let group_aad = b"Alice's test group";
    let framing_parameters = FramingParameters::new(group_aad, WireFormat::PublicMessage);

    let (alice_credential_with_key, _, alice_signature_keys, _pk) =
        setup_client("Alice", ciphersuite, backend);
    let (_, bob_kpb, _, _) = setup_client("Bob", ciphersuite, backend);
    let (_, charlie_kpb, _, _) = setup_client("Charlie", ciphersuite, backend);

    let mut alice_group = CoreGroup::builder(
        GroupId::random(backend),
        config::CryptoConfig::with_default_version(ciphersuite),
        alice_credential_with_key,
    )
    .build(backend, &alice_signature_keys)
    .expect("Error creating CoreGroup.");

    // Adding Bob
    let bob_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            bob_kpb.key_package().clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal");

    let bob_add_proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&bob_add_proposal_store)
        .force_self_update(false)
        .build();
    let add_commit_result = alice_group
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating commit");

    alice_group
        .merge_commit(backend, add_commit_result.staged_commit)
        .expect("error merging pending commit");

    let ratchet_tree = alice_group.public_group().export_ratchet_tree();

    let mut bob_group = CoreGroup::new_from_welcome(
        add_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        bob_kpb,
        backend,
        ResumptionPskStore::new(1024),
    )
    .expect("Error joining group.");

    // Alice adds Charlie and removes Bob in the same commit.
    let bob_index = alice_group
        .public_group()
        .members()
        .find(
            |Member {
                 index: _,
                 credential,
                 ..
             }| credential.identity() == b"Bob",
        )
        .expect("Couldn't find Bob in tree.")
        .index;
    let bob_remove_proposal = alice_group
        .create_remove_proposal(framing_parameters, bob_index, &alice_signature_keys)
        .expect("Could not create proposal");

    let charlie_add_proposal = alice_group
        .create_add_proposal(
            framing_parameters,
            charlie_kpb.key_package().clone(),
            &alice_signature_keys,
        )
        .expect("Could not create proposal");

    let mut remove_add_proposal_store = ProposalStore::from_queued_proposal(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            backend,
            bob_remove_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    remove_add_proposal_store.add(
        QueuedProposal::from_authenticated_content_by_ref(
            ciphersuite,
            backend,
            charlie_add_proposal,
        )
        .expect("Could not create QueuedProposal."),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .proposal_store(&remove_add_proposal_store)
        .build();
    let remove_add_commit_result = alice_group
        .create_commit(params, backend, &alice_signature_keys)
        .expect("Error creating commit");

    let staged_commit = bob_group
        .read_keys_and_stage_commit(
            &remove_add_commit_result.commit,
            &remove_add_proposal_store,
            &[],
            backend,
        )
        .expect("error staging commit");
    bob_group
        .merge_commit(backend, staged_commit)
        .expect("Error merging commit.");

    alice_group
        .merge_commit(backend, remove_add_commit_result.staged_commit)
        .expect("Error merging commit.");

    let ratchet_tree = alice_group.public_group().export_ratchet_tree();

    let charlie_group = CoreGroup::new_from_welcome(
        remove_add_commit_result
            .welcome_option
            .expect("An unexpected error occurred."),
        Some(ratchet_tree.into()),
        charlie_kpb,
        backend,
        ResumptionPskStore::new(1024),
    )
    .expect("Error joining group.");

    // We can now check that Bob correctly processed his and applied the changes
    // to his tree after he was removed by comparing membership lists. In
    // particular, Bob's list should show that he was removed and Charlie was
    // added.
    let alice_members = alice_group.public_group().members();

    let bob_members = bob_group.public_group().members();

    let charlie_members = charlie_group.public_group().members();

    for (alice_member, (bob_member, charlie_member)) in
        alice_members.zip(bob_members.zip(charlie_members))
    {
        // Note that we can't compare encryption keys for Bob because they
        // didn't get updated.
        assert_eq!(alice_member.index, bob_member.index);
        assert_eq!(
            alice_member.credential.identity(),
            bob_member.credential.identity()
        );
        assert_eq!(alice_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.index, bob_member.index);
        assert_eq!(
            charlie_member.credential.identity(),
            bob_member.credential.identity()
        );
        assert_eq!(charlie_member.signature_key, bob_member.signature_key);
        assert_eq!(charlie_member.encryption_key, alice_member.encryption_key);
    }

    let mut bob_members = bob_group.public_group().members();

    assert_eq!(bob_members.next().unwrap().credential.identity(), b"Alice");
    assert_eq!(
        bob_members.next().unwrap().credential.identity(),
        b"Charlie"
    );
}
