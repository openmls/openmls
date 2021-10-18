use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use crate::{
    ciphersuite::signable::Verifiable,
    config::Config,
    group::WireFormat,
    key_packages::KeyPackageBundle,
    messages::{
        CredentialBundle, CredentialType, LeafIndex, MlsGroup, MlsGroupConfig, PublicGroupState,
    },
    prelude::FramingParameters,
};

/// Tests the creation of a `PublicGroupState` and verifies it was correctly
/// signed
#[test]
fn test_pgs() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        let group_aad = b"Alice's test group";
        let framing_parameters = FramingParameters::new(group_aad, WireFormat::MlsPlaintext);

        // Define credential bundles
        let alice_credential_bundle = CredentialBundle::new(
            "Alice".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &crypto,
        )
        .unwrap();
        let bob_credential_bundle = CredentialBundle::new(
            "Bob".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &crypto,
        )
        .unwrap();

        // Generate KeyPackages
        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();

        // Alice creates a group
        let group_id = [1, 2, 3, 4];
        let mut group_alice = MlsGroup::new(
            &group_id,
            ciphersuite.name(),
            &crypto,
            alice_key_package_bundle,
            MlsGroupConfig::default(),
            None, /* Initial PSK */
            None, /* MLS version */
        )
        .expect("Could not create group.");

        // Alice adds Bob
        let bob_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                &crypto,
            )
            .expect("Could not create proposal.");
        let (commit, _welcome_option, kpb_option) = match group_alice.create_commit(
            framing_parameters,
            &alice_credential_bundle,
            &[&bob_add_proposal],
            &[],
            true,
            None,
            &crypto,
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
                &crypto,
            )
            .expect("Could not apply Commit");

        let pgs = group_alice
            .export_public_group_state(&crypto, &alice_credential_bundle)
            .expect("Could not export the public group state");

        // Make sure Alice is the signer
        assert_eq!(pgs.signer_index, LeafIndex::from(0u32));

        // Verify the signature
        assert!(pgs
            .verify_no_out(&crypto, alice_credential_bundle.credential())
            .is_ok());

        // Test codec
        let encoded = pgs.tls_serialize_detached().expect("Could not encode");
        let decoded =
            PublicGroupState::tls_deserialize(&mut encoded.as_slice()).expect("Could not decode");

        assert_eq!(decoded, pgs);
    }
}
