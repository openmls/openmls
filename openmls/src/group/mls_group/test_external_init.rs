use crate::{
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    group::MlsGroupConfig,
    messages::VerifiablePublicGroupState,
    prelude::KeyPackageBundle,
};

use tls_codec::{Deserialize, Serialize};

use super::MlsGroup;

#[test]
/// Test what happens if the KEM ciphertext for the receiver in the UpdatePath
/// is broken.
fn test_external_init() {
    for ciphersuite in Config::supported_ciphersuites() {
        // Basic group setup with alice and bob.
        let group_aad = b"Alice's test group";

        // Define credential bundles
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

        // Generate KeyPackages
        let alice_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
                .unwrap();

        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
                .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        // === Alice creates a group ===
        let group_id = [1, 2, 3, 4];
        let mut group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            alice_key_package_bundle,
            MlsGroupConfig::default(),
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .unwrap();

        // === Alice adds Bob ===
        let bob_add_proposal = group_alice
            .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
            .expect("Could not create proposal.");
        let epoch_proposals = &[&bob_add_proposal];
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = group_alice
            .create_commit(
                group_aad,
                &alice_credential_bundle,
                epoch_proposals,
                &[],
                false,
                None,
            )
            .expect("Error creating commit");

        group_alice
            .apply_commit(&mls_plaintext_commit, epoch_proposals, &[], None)
            .expect("error applying commit");
        let ratchet_tree = group_alice.tree().public_key_tree_copy();

        let group_bob = MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
            None,
        )
        .unwrap();

        // Now set up charly and try to init externally.
        // Define credential bundles
        let charly_credential_bundle = CredentialBundle::new(
            "Charly".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
        )
        .unwrap();

        // Have Alice export everything that Charly needs.
        let pgs_encoded = group_alice
            .export_public_group_state(&alice_credential_bundle)
            .expect("Error exporting PGS")
            .tls_serialize_detached()
            .expect("Error serializing PGS");
        let verifiable_public_group_state =
            VerifiablePublicGroupState::tls_deserialize(pgs_encoded)
                .expect("Error deserializing PGS")
                .into();
        let nodes_option = group_alice.tree().public_key_tree_copy();

        let group_charly = MlsGroup::new_from_external_init(
            Some(nodes_option),
            None, // PSK fetcher
            group_aad,
            &charly_credential_bundle,
            &[], // proposals by reference
            &[], // proposals by value
            verifiable_public_group_state,
        )
        .expect("Error initializing group externally.");
    }
}
