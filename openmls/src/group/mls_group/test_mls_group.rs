use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto,
    types::{CryptoError, HpkeCiphertext},
    OpenMlsCryptoProvider,
};
use tls_codec::Serialize;

use crate::{
    ciphersuite::{signable::Signable, AeadNonce},
    group::{create_commit_params::CreateCommitParams, CoreGroup, GroupEpoch},
    messages::{Commit, ConfirmationTag, EncryptedGroupSecrets, GroupInfoPayload},
    prelude::*,
    schedule::psk::*,
    test_utils::*,
    tree::{index::LeafIndex, TreeError, UpdatePath, UpdatePathNode},
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
        CoreGroup::load(file_in).expect("Could not deserialize MlsGroup");

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
        let signer_index = LeafIndex::from(8u32);
        let group_info = GroupInfoPayload::new(
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            &Vec::new(),
            &extensions,
            confirmation_tag,
            signer_index,
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

        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            backend,
        )
        .expect("An unexpected error occurred.");
        let group_info = group_info
            .sign(backend, &alice_credential_bundle)
            .expect("Error signing group info");

        let key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            backend,
            vec![],
        )
        .expect("An unexpected error occurred.");

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

        let error = CoreGroup::new_from_welcome_internal(
            broken_welcome,
            None,
            key_package_bundle,
            None,
            backend,
        )
        .expect_err("Creation of MLS group from a broken Welcome was successful.");

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
    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    let commit = match mls_plaintext_commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Wrong content type"),
    };
    assert!(!commit.has_path() && kpb_option.is_none());
    // Check that the function returned a Welcome message
    assert!(welcome_bundle_alice_bob_option.is_some());

    println!(
        " *** Confirmation tag: {:?}",
        mls_plaintext_commit.confirmation_tag()
    );

    let staged_commit = alice_group
        .stage_commit(&mls_plaintext_commit, &proposal_store, &[], None, backend)
        .expect("error staging commit");
    alice_group.merge_commit(staged_commit);
    let ratchet_tree = alice_group.tree().public_key_tree_copy();

    let group_bob = CoreGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        None,
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
    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_bob)
            .expect("Could not create StagedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&bob_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (mls_plaintext_commit, _welcome_option, _kpb_option) = group_bob
        .create_commit(params, backend)
        .expect("An unexpected error occurred.");

    // Now we break Alice's HPKE ciphertext in Bob's commit by breaking
    // apart the commit, manipulating the ciphertexts and the piecing it
    // back together.
    let commit = match mls_plaintext_commit.content() {
        MlsPlaintextContentType::Commit(commit) => commit,
        _ => panic!("Bob created a commit, which does not contain an actual commit."),
    };

    let commit = commit.clone();

    let path = commit.path.expect("An unexpected error occurred.");

    // For simplicity, let's just break all the ciphertexts.
    let mut new_nodes = Vec::new();
    for node in path.nodes.iter() {
        let mut new_eps = Vec::new();
        for c in node.encrypted_path_secret.iter() {
            let mut c_copy = c.clone();
            flip_last_byte(&mut c_copy);
            new_eps.push(c_copy);
        }
        let node = UpdatePathNode {
            public_key: node.public_key.clone(),
            encrypted_path_secret: new_eps.into(),
        };
        new_nodes.push(node);
    }

    let broken_path = UpdatePath {
        leaf_key_package: path.leaf_key_package,
        nodes: new_nodes.into(),
    };

    // Now let's create a new commit from out broken update path.
    let broken_commit = Commit {
        proposals: commit.proposals,
        path: Some(broken_path),
    };

    let mut broken_plaintext = MlsPlaintext::new_commit(
        framing_parameters,
        mls_plaintext_commit.sender_index(),
        broken_commit,
        &bob_credential_bundle,
        group_bob.context(),
        backend,
    )
    .expect("Could not create plaintext.");

    broken_plaintext.set_confirmation_tag(
        mls_plaintext_commit
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
            group_bob.epoch_secrets.membership_key(),
        )
        .expect("Could not add membership key");

    let staged_commit_res =
        alice_group.stage_commit(&broken_plaintext, &proposal_store, &[], None, backend);
    assert_eq!(
        staged_commit_res.expect_err("Successful processing of a broken commit."),
        CoreGroupError::StageCommitError(StageCommitError::DecryptionFailure(
            TreeError::CryptoError(CryptoError::HpkeDecryptionError)
        ))
    );
}

// Test several scenarios when PSKs are used in a group
#[apply(ciphersuites_and_backends)]
fn test_psks(ciphersuite: &'static Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    fn psk_fetcher(psks: &PreSharedKeys, ciphersuite: &'static Ciphersuite) -> Option<Vec<Secret>> {
        let psk_id = vec![1u8, 2, 3];
        let secret = Secret::from_slice(&[6, 6, 6], ProtocolVersion::Mls10, ciphersuite);

        let psk = &psks.psks[0];
        if psk.psk_type == PskType::External {
            if let Psk::External(external_psk) = &psk.psk {
                if external_psk.psk_id() == psk_id {
                    Some(vec![secret])
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }

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
    let external_psk_bundle = ExternalPskBundle::new(ciphersuite, backend, secret, psk_id)
        .expect("Could not create ExternalPskBundle.");
    let preshared_key_id = external_psk_bundle.to_presharedkey_id();
    let initial_psk = PskSecret::new(
        ciphersuite,
        backend,
        &[preshared_key_id.clone()],
        &[external_psk_bundle.secret().clone()],
    )
    .expect("Could not create PskSecret");
    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_psk(initial_psk)
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

    let mut proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, bob_add_proposal)
            .expect("Could not create StagedProposal."),
    );
    proposal_store.add(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, psk_proposal)
            .expect("Could not create StagedProposal."),
    );
    log::info!(" >>> Creating commit ...");
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .psk_fetcher_option(Some(psk_fetcher))
        .build();
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    log::info!(" >>> Staging & merging commit ...");

    let staged_commit = alice_group
        .stage_commit(
            &mls_plaintext_commit,
            &proposal_store,
            &[],
            Some(psk_fetcher),
            backend,
        )
        .expect("error staging commit");
    alice_group.merge_commit(staged_commit);
    let ratchet_tree = alice_group.tree().public_key_tree_copy();

    let group_bob = CoreGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.expect("An unexpected error occurred."),
        Some(ratchet_tree),
        bob_key_package_bundle,
        Some(psk_fetcher),
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
    let proposal_store = ProposalStore::from_staged_proposal(
        StagedProposal::from_mls_plaintext(ciphersuite, backend, update_proposal_bob)
            .expect("Could not create StagedProposal."),
    );
    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&bob_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (_mls_plaintext_commit, _welcome_option, _kpb_option) = group_bob
        .create_commit(params, backend)
        .expect("An unexpected error occurred.");
}
