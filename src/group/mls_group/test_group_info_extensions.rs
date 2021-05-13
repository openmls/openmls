use super::*;

use crate::prelude::*;

// === Custom Extension ===

#[derive(Serialize, Deserialize, PartialEq, Clone, Debug)]
struct AnswerToLifeExtension {
    answer: u8,
}

impl Default for AnswerToLifeExtension {
    fn default() -> Self {
        AnswerToLifeExtension { answer: 42 }
    }
}

impl GroupInfoExtension for AnswerToLifeExtension {
    fn extension_type(&self) -> ExtensionType {
        ExtensionType::Custom(0xff01)
    }
}

impl Codec for AnswerToLifeExtension {
    fn encode(&self, buffer: &mut Vec<u8>) -> Result<(), crate::codec::CodecError> {
        self.answer.encode(buffer).unwrap();
        Ok(())
    }

    fn decode(mut cursor: &mut Cursor) -> Result<Self, crate::codec::CodecError> {
        let answer = u8::decode(&mut cursor)?;
        Ok(Self { answer })
    }
}

#[test]
fn custom_extension_group_info_extension_serialization() {
    let answer_to_life_extension = AnswerToLifeExtension::default();
    let encoded = answer_to_life_extension
        .encode_detached()
        .expect("Could not encode AnswerToLifeExtension");
    let decoded = AnswerToLifeExtension::decode_detached(&encoded)
        .expect("Could not decode AnswerToLifeExtension");
    assert_eq!(decoded, answer_to_life_extension);
}

// Test several scenarios when PSKs are used in a group
ctest_ciphersuites!(test_custom_group_info_extension, test(ciphersuite_name: CiphersuiteName) {

    let ciphersuite = Config::ciphersuite(ciphersuite_name).unwrap();

    // Basic group setup.
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

    let mut alice_group = MlsGroup::new(
        &group_id,
        ciphersuite.name(),
        alice_key_package_bundle,
        false, /* use ratchet tree extension */
        None, /* PSK fetcher */
        None, /* MLS version */
    )
    .unwrap();

    // === Custom extension ===

    let answer_to_life = AnswerToLifeExtension::default();

    // === Alice adds Bob ===
    let bob_add_proposal = alice_group
        .create_add_proposal(group_aad, &alice_credential_bundle, bob_key_package.clone())
        .expect("Could not create proposal");
    let epoch_proposals = &[&bob_add_proposal];
    log::info!(" >>> Creating commit ...");
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option, _kpb_option) = alice_group
        .create_commit(
            group_aad,
            &alice_credential_bundle,
            epoch_proposals,
            &[],
            false,
            None, /* PSK fetcher */
            vec![answer_to_life.to_extension_struct().expect("Could not convert extension to ExtensionStruct")], /* Extensions */
        )
        .expect("Error creating commit");

    log::info!(" >>> Applying commit ...");
    alice_group
        .apply_commit(
            &mls_plaintext_commit,
            epoch_proposals,
            &[],
            None,
        )
        .expect("error applying commit");
    let ratchet_tree = alice_group.tree().public_key_tree_copy();

    // === Bob joins ===

    let (group_bob, extensions) = MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        Some(ratchet_tree),
        bob_key_package_bundle,
        None,
    )
    .expect("Could not create new group from Welcome");

    // Make sure only one extension was returned
    assert_eq!(extensions.len(), 1);

    // Make sure we received the right extension
    let extension = AnswerToLifeExtension::from_extension_struct(extensions[0].clone())
        .expect("Could not convert extension from ExtensionStruct");
    assert_eq!(extension.answer, 42);

    // === Bob updates and commits ===
    let bob_update_key_package_bundle =
        KeyPackageBundle::new(&[ciphersuite.name()], &bob_credential_bundle, Vec::new())
            .unwrap();

    let update_proposal_bob = group_bob
        .create_update_proposal(
            &[],
            &bob_credential_bundle,
            bob_update_key_package_bundle.key_package().clone(),
        )
        .expect("Could not create proposal.");
    let (_mls_plaintext_commit, _welcome_option, _kpb_option) = group_bob
        .create_commit(
            &[],
            &bob_credential_bundle,
            &[&update_proposal_bob],
            &[],
            false, /* force self update */
            None,
            vec![], /* Extensions */
        )
        .unwrap();

});
