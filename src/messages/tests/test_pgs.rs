use crate::{
    key_packages::KeyPackageBundle,
    messages::{
        Codec, Config, CredentialBundle, CredentialType, LeafIndex, MlsGroup, PublicGroupState,
    },
};

/// Tests the creation of a `PublicGroupState` and verifies it was correctly
/// signed
#[test]
fn test_pgs() {
    for ciphersuite in Config::supported_ciphersuites() {
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
        let bob_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
                .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let alice_key_package_bundle =
            KeyPackageBundle::new(&[ciphersuite.name()], &alice_credential_bundle, Vec::new())
                .unwrap();

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let mut group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            alice_key_package_bundle,
            false, /* use ratchet tree extension */
            None,  /* Initial PSK */
            None,  /* MLS version */
        )
        .expect("Could not create group.");

        // Alice adds Bob
        let bob_add_proposal = group_alice
            .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
            .expect("Could not create proposal.");
        let (commit, _welcome_option, kpb_option) = match group_alice.create_commit(
            group_aad,
            &alice_credential_bundle,
            &[&bob_add_proposal],
            &[],
            true,
            None,
            vec![], /* Extensions */
        ) {
            Ok(c) => c,
            Err(e) => panic!("Error creating commit: {:?}", e),
        };

        group_alice
            .apply_commit(
                &commit,
                &[&bob_add_proposal],
                &[kpb_option.expect("No KeyPackageBundle")],
                None,
            )
            .expect("Could not apply Commit");

        let pgs = group_alice
            .export_public_group_state(&alice_credential_bundle, vec![] /* Extensions */)
            .expect("Could not export the public group state");

        // Make sure Alice is the signer
        assert_eq!(pgs.signer_index, LeafIndex::from(0u32));

        // Verify the signature
        assert!(pgs.verify(&alice_credential_bundle).is_ok());

        // Test codec
        let encoded = pgs.encode_detached().expect("Could not encode");
        let decoded = PublicGroupState::decode_detached(&encoded).expect("Could not decode");

        assert_eq!(decoded, pgs);
    }
}
