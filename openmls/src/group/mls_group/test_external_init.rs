use crate::{
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    group::{create_commit::Proposals, MlsGroupConfig, WireFormat},
    messages::public_group_state::{PublicGroupState, VerifiablePublicGroupState},
    prelude::{plaintext::MlsPlaintextContentType, FramingParameters, KeyPackageBundle},
};

use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize, Serialize};

use super::MlsGroup;

#[test]
/// Test what happens if the KEM ciphertext for the receiver in the UpdatePath
/// is broken.
fn test_external_init() {
    let crypto = OpenMlsRustCrypto::default();
    for ciphersuite in Config::supported_ciphersuites() {
        // Basic group setup.
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
        let alice_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &alice_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();

        let bob_key_package_bundle = KeyPackageBundle::new(
            &[ciphersuite.name()],
            &bob_credential_bundle,
            &crypto,
            Vec::new(),
        )
        .unwrap();
        let bob_key_package = bob_key_package_bundle.key_package();

        // === Alice creates a group ===
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
        .unwrap();

        // === Alice adds Bob ===
        let bob_add_proposal = group_alice
            .create_add_proposal(
                framing_parameters,
                &alice_credential_bundle,
                bob_key_package.clone(),
                &crypto,
            )
            .expect("Could not create proposal.");
        let epoch_proposals = &[&bob_add_proposal];
        let (mls_plaintext_commit, welcome_bundle_alice_bob_option, kpb_option) = group_alice
            .create_commit(
                framing_parameters,
                &alice_credential_bundle,
                Proposals {
                    proposals_by_reference: epoch_proposals,
                    proposals_by_value: &[],
                },
                false,
                None,
                &crypto,
            )
            .expect("Error creating commit");

        group_alice
            .apply_commit(&mls_plaintext_commit, epoch_proposals, &[], None, &crypto)
            .expect("error applying commit");
        let ratchet_tree = group_alice.tree().public_key_tree_copy();

        let group_bob = MlsGroup::new_from_welcome(
            welcome_bundle_alice_bob_option.unwrap(),
            Some(ratchet_tree),
            bob_key_package_bundle,
            None,
            &crypto,
        )
        .unwrap();

        // Now set up charly and try to init externally.
        // Define credential bundles
        let charly_credential_bundle = CredentialBundle::new(
            "Charly".into(),
            CredentialType::Basic,
            ciphersuite.signature_scheme(),
            &crypto,
        )
        .unwrap();

        // Have Alice export everything that Charly needs.
        let pgs_encoded: Vec<u8> = group_alice
            .export_public_group_state(&crypto, &alice_credential_bundle)
            .expect("Error exporting PGS")
            .tls_serialize_detached()
            .expect("Error serializing PGS");
        let verifiable_public_group_state =
            VerifiablePublicGroupState::tls_deserialize(&mut pgs_encoded.as_slice())
                .expect("Error deserializing PGS")
                .into();
        let nodes_option = group_alice.tree().public_key_tree_copy();

        let group_charly = MlsGroup::new_from_external_init(
            framing_parameters,
            Some(nodes_option),
            None, // PSK fetcher
            &charly_credential_bundle,
            &[], // proposals by reference
            &[], // proposals by value
            verifiable_public_group_state,
            &crypto,
        )
        .expect("Error initializing group externally.");
    }
}
