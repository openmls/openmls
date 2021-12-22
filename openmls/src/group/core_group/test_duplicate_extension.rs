//! # Ratchet tree extensions unit test
use super::*;

use crate::{credentials::*, messages::GroupSecrets, schedule::KeySchedule, test_utils::*};
use core_group::create_commit_params::CreateCommitParams;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsCryptoProvider;
use tls_codec::Deserialize;

// This tests the ratchet tree extension to test if the duplicate detection works
#[apply(ciphersuites_and_backends)]
fn duplicate_ratchet_tree_extension(
    ciphersuite: &'static Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
) {
    // Basic group setup.
    let group_aad = b"Alice's test group";

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

    let config = CoreGroupConfig {
        add_ratchet_tree_extension: true,
        ..CoreGroupConfig::default()
    };

    let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

    let mut alice_group = CoreGroup::builder(GroupId::random(backend), alice_key_package_bundle)
        .with_config(config)
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
            .expect("Could not create StagingProposal"),
    );

    let params = CreateCommitParams::builder()
        .framing_parameters(framing_parameters)
        .credential_bundle(&alice_credential_bundle)
        .proposal_store(&proposal_store)
        .force_self_update(false)
        .build();
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(params, backend)
        .expect("Error creating commit");

    let staged_commit = alice_group
        .stage_commit(&mls_plaintext_commit, &proposal_store, &[], backend)
        .expect("error staging commit");
    alice_group
        .merge_commit(staged_commit)
        .expect("error merging commit");

    let mut welcome = welcome_bundle_alice_bob_option.expect("Expected a Welcome message");

    //  === Duplicate the ratchet tree extension ===

    // Find key_package in welcome secrets
    let egs = CoreGroup::find_key_package_from_welcome_secrets(
        bob_key_package_bundle.key_package(),
        welcome.secrets(),
        backend,
    )
    .expect("Could not hash KeyPackage.")
    .expect("JoinerSecret not found");

    let group_secrets_bytes = backend
        .crypto()
        .hpke_open(
            ciphersuite.hpke_config(),
            &egs.encrypted_group_secrets,
            bob_key_package_bundle.private_key().as_slice(),
            &[],
            &[],
        )
        .expect("Could not decrypt group secrets");
    let group_secrets = GroupSecrets::tls_deserialize(&mut group_secrets_bytes.as_slice())
        .expect("Could not decode GroupSecrets")
        .config(ciphersuite, ProtocolVersion::default());
    let joiner_secret = group_secrets.joiner_secret;

    // Prepare the PskSecret
    let psk_secret = PskSecret::new(ciphersuite, backend, group_secrets.psks.psks())
        .expect("An unexpected error occurred.");

    // Create key schedule
    let key_schedule = KeySchedule::init(ciphersuite, backend, joiner_secret, psk_secret)
        .expect("Could not create KeySchedule.");

    // Derive welcome key & noce from the key schedule
    let (welcome_key, welcome_nonce) = key_schedule
        .welcome(backend)
        .expect("Expected a WelcomeSecret")
        .derive_welcome_key_nonce(backend)
        .expect("Could not derive welcome nonce.");

    let group_info_bytes = welcome_key
        .aead_open(backend, welcome.encrypted_group_info(), &[], &welcome_nonce)
        .map_err(|_| WelcomeError::GroupInfoDecryptionFailure)
        .expect("Could not decrypt GroupInfo");
    let mut group_info = GroupInfo::tls_deserialize(&mut group_info_bytes.as_slice())
        .expect("Could not decode GroupInfo");

    // Duplicate extensions
    let extensions = group_info.other_extensions();
    let duplicate_extensions = vec![extensions[0].clone(), extensions[0].clone()];
    group_info.set_other_extensions(duplicate_extensions);

    // Put everything back together
    let group_info = group_info
        .re_sign(&bob_credential_bundle, backend)
        .expect("Error re-signing GroupInfo");

    let encrypted_group_info = welcome_key
        .aead_seal(
            backend,
            &group_info
                .tls_serialize_detached()
                .expect("Could not encode GroupInfo"),
            &[],
            &welcome_nonce,
        )
        .expect("An unexpected error occurred.");

    welcome.set_encrypted_group_info(encrypted_group_info);

    // Try to join group
    let error = CoreGroup::new_from_welcome(welcome, None, bob_key_package_bundle, backend).err();

    // We expect an error because the ratchet tree is duplicated
    assert_eq!(
        error.expect("We expected an error"),
        CoreGroupError::WelcomeError(WelcomeError::DuplicateRatchetTreeExtension)
    );
}
