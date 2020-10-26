use maelstrom::ciphersuite::*;
use maelstrom::creds::*;
use maelstrom::framing::*;
use maelstrom::group::*;
use maelstrom::key_packages::*;

#[test]
fn create_commit_optional_path() {
    use maelstrom::extensions::*;
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_aad = b"Alice's test group";

    // Define identities
    let alice_identity = Identity::new(ciphersuite_name, "Alice".into());
    let bob_identity = Identity::new(ciphersuite_name, "Bob".into());

    // Define credentials
    let alice_credential = BasicCredential::from(&alice_identity);
    let bob_credential = BasicCredential::from(&bob_identity);

    // Signature keys
    let alice_signature_key = &alice_identity.get_signature_key_pair().get_private_key();
    let bob_signature_key = &bob_identity.get_signature_key_pair().get_private_key();

    // Mandatory extensions
    let capabilities_extension = Box::new(CapabilitiesExtension::default());
    let lifetime_extension = Box::new(LifetimeExtension::new(60));
    let mandatory_extensions: Vec<Box<dyn Extension>> =
        vec![capabilities_extension, lifetime_extension];

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        ciphersuite_name,
        alice_signature_key,
        Credential::from(MLSCredentialType::Basic(alice_credential.clone())),
        mandatory_extensions.clone(),
    );

    let bob_key_package_bundle = KeyPackageBundle::new(
        ciphersuite_name,
        bob_signature_key,
        Credential::from(MLSCredentialType::Basic(bob_credential)),
        mandatory_extensions.clone(),
    );
    let bob_key_package = bob_key_package_bundle.get_key_package();

    let alice_update_key_package_bundle = KeyPackageBundle::new(
        ciphersuite_name,
        alice_signature_key,
        Credential::from(MLSCredentialType::Basic(alice_credential)),
        mandatory_extensions,
    );
    let alice_update_key_package = alice_update_key_package_bundle.get_key_package();
    assert!(alice_update_key_package.verify().is_ok());

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let mut group_alice_1234 = MlsGroup::new(&group_id, ciphersuite_name, alice_key_package_bundle);

    // Alice adds Bob with forced self-update
    let bob_add_proposal = group_alice_1234.create_add_proposal(
        group_aad,
        alice_signature_key,
        bob_key_package.clone(),
    );
    let epoch_proposals = vec![bob_add_proposal];
    let (mls_plaintext_commit, _welcome_bundle_alice_bob_option) = match group_alice_1234
        .create_commit(group_aad, alice_signature_key, epoch_proposals, true)
    {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let commit = match &mls_plaintext_commit.content {
        MLSPlaintextContentType::Commit((commit, _)) => commit,
        _ => panic!(),
    };
    assert!(commit.path.is_some());

    // Alice adds Bob without forced self-update
    let bob_add_proposal = group_alice_1234.create_add_proposal(
        group_aad,
        alice_signature_key,
        bob_key_package.clone(),
    );
    let epoch_proposals = vec![bob_add_proposal];
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option) = match group_alice_1234
        .create_commit(
            group_aad,
            alice_signature_key,
            epoch_proposals.clone(),
            false,
        ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let commit = match &mls_plaintext_commit.content {
        MLSPlaintextContentType::Commit((commit, _)) => commit,
        _ => panic!(),
    };
    assert!(commit.path.is_none());

    // Alice applies Commit
    match group_alice_1234.apply_commit(mls_plaintext_commit, epoch_proposals, vec![]) {
        Ok(_) => {}
        Err(e) => panic!("Error applying commit: {:?}", e),
    };
    let ratchet_tree = group_alice_1234.tree().get_public_key_tree();

    // Bob creates group from Welcome
    let mut group_bob_1234 = match MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        Some(ratchet_tree),
        bob_key_package_bundle,
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {:?}", e),
    };

    assert_eq!(
        group_alice_1234.tree().get_public_key_tree(),
        group_alice_1234.tree().get_public_key_tree()
    );

    // Alice updates
    let alice_update_proposal = group_alice_1234.create_update_proposal(
        group_aad,
        alice_signature_key,
        alice_update_key_package.clone(),
    );
    let proposals = vec![alice_update_proposal];

    // Only UpdateProposal
    let (commit_mls_plaintext, _welcome_option) = match group_alice_1234.create_commit(
        group_aad,
        alice_signature_key,
        proposals.clone(),
        false,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let (commit, _confirmation_tag) = match &commit_mls_plaintext.content {
        MLSPlaintextContentType::Commit((commit, confirmation_tag)) => (commit, confirmation_tag),
        _ => panic!(),
    };
    assert!(commit.path.is_some());

    // Apply UpdateProposal
    /*
        match group_alice_1234.apply_commit(
            commit_mls_plaintext.clone(),
            proposals.clone(),
            vec![alice_update_key_package_bundle],
        ) {
            Ok(()) => {}
            Err(e) => panic!("Error applying commit: {:?}", e),
        }
    */

    match group_bob_1234.apply_commit(commit_mls_plaintext, proposals, vec![]) {
        Ok(()) => {}
        Err(e) => panic!("Error applying commit: {:?}", e),
    }
}
#[test]
fn basic_group_setup() {
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_aad = b"Alice's test group";

    // Define identities
    let alice_identity = Identity::new(ciphersuite_name, "Alice".into());
    let bob_identity = Identity::new(ciphersuite_name, "Bob".into());

    // Define credentials
    let alice_credential = BasicCredential::from(&alice_identity);
    let bob_credential = BasicCredential::from(&bob_identity);

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        ciphersuite_name,
        &bob_identity.get_signature_key_pair().get_private_key(), // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Credential::from(MLSCredentialType::Basic(bob_credential)), // TODO: this consumes the credential!
        Vec::new(),
    );
    let bob_key_package = bob_key_package_bundle.get_key_package();

    let alice_key_package_bundle = KeyPackageBundle::new(
        ciphersuite_name,
        &alice_identity.get_signature_key_pair().get_private_key(), // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Credential::from(MLSCredentialType::Basic(alice_credential)),
        Vec::new(),
    );

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let group_alice_1234 = MlsGroup::new(&group_id, ciphersuite_name, alice_key_package_bundle);

    // Alice adds Bob
    let bob_add_proposal = group_alice_1234.create_add_proposal(
        group_aad,
        &alice_identity.get_signature_key_pair().get_private_key(),
        bob_key_package.clone(),
    );
    let _commit = match group_alice_1234.create_commit(
        group_aad,
        &alice_identity.get_signature_key_pair().get_private_key(),
        vec![bob_add_proposal],
        true,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
}

#[test]
fn group_operations() {
    use maelstrom::extensions::*;
    use maelstrom::utils::*;
    let ciphersuite_name = CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let group_aad = b"Alice's test group";

    // Define identities
    let alice_identity = Identity::new(ciphersuite_name, "Alice".into());
    let bob_identity = Identity::new(ciphersuite_name, "Bob".into());

    // Define credentials
    let alice_credential = BasicCredential::from(&alice_identity);
    let bob_credential = BasicCredential::from(&bob_identity);

    // Signature keys
    let alice_signature_key = &alice_identity.get_signature_key_pair().get_private_key();
    let bob_signature_key = &bob_identity.get_signature_key_pair().get_private_key();

    // Mandatory extensions
    let capabilities_extension = Box::new(CapabilitiesExtension::default());
    let lifetime_extension = Box::new(LifetimeExtension::new(60));
    let mandatory_extensions: Vec<Box<dyn Extension>> =
        vec![capabilities_extension, lifetime_extension];

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        ciphersuite_name,
        alice_signature_key,
        Credential::from(MLSCredentialType::Basic(alice_credential)),
        mandatory_extensions.clone(),
    );

    let bob_key_package_bundle = KeyPackageBundle::new(
        ciphersuite_name,
        bob_signature_key,
        Credential::from(MLSCredentialType::Basic(bob_credential)),
        mandatory_extensions,
    );
    let bob_key_package = bob_key_package_bundle.get_key_package();

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let mut group_alice_1234 = MlsGroup::new(&group_id, ciphersuite_name, alice_key_package_bundle);

    // Alice adds Bob
    let bob_add_proposal = group_alice_1234.create_add_proposal(
        group_aad,
        alice_signature_key,
        bob_key_package.clone(),
    );
    let epoch_proposals = vec![bob_add_proposal];
    let (mls_plaintext_commit, welcome_bundle_alice_bob_option) = match group_alice_1234
        .create_commit(
            group_aad,
            alice_signature_key,
            epoch_proposals.clone(),
            false, // TODO force update seems broken
        ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let commit = match &mls_plaintext_commit.content {
        MLSPlaintextContentType::Commit((commit, _)) => commit,
        _ => panic!(),
    };
    assert!(commit.path.is_none());

    match group_alice_1234.apply_commit(mls_plaintext_commit, epoch_proposals, vec![]) {
        Ok(_) => {}
        Err(e) => panic!("Error applying commit: {:?}", e),
    };
    let ratchet_tree = group_alice_1234.tree().get_public_key_tree();

    let mut group_bob = match MlsGroup::new_from_welcome(
        welcome_bundle_alice_bob_option.unwrap(),
        Some(ratchet_tree),
        bob_key_package_bundle,
    ) {
        Ok(group) => group,
        Err(e) => panic!("Error creating group from Welcome: {:?}", e),
    };

    assert_eq!(
        group_alice_1234.tree().get_public_key_tree(),
        group_alice_1234.tree().get_public_key_tree()
    );
    _print_tree(&group_alice_1234.tree(), "Alice added Bob");

    // Alice sends a message to Bob
    let message_alice = [1, 2, 3];
    let mls_ciphertext_alice =
        group_alice_1234.create_application_message(&[], &message_alice, &alice_signature_key);
    let mls_plaintext_bob = match group_bob.decrypt(mls_ciphertext_alice) {
        Ok(mls_plaintext) => mls_plaintext,
        Err(e) => panic!("Error decrypting MLSCiphertext: {:?}", e),
    };
    assert_eq!(
        message_alice,
        mls_plaintext_bob.as_application_message().unwrap()
    );
}
/*
    // Bob updates and commits
    let update_proposal_bob = group_bob.create_update_proposal(None);
    let (commit2, ms2, _) = group_bob.create_commit(None);

    group_alice_1234.process_proposal(update_proposal_bob);
    group_alice_1234.process_commit(commit2.clone());
    group_bob.process_commit(commit2);

    group_alice_1234.tree.print(&format!("\n{:?}", ms2));

    // Alice updates and commits
    let update_proposal_alice = group_alice_1234.create_update_proposal(None);
    let (commit3, ms3, _) = group_alice_1234.create_commit(None);

    group_bob.process_proposal(update_proposal_alice);
    group_alice_1234.process_commit(commit3.clone());
    group_bob.process_commit(commit3);

    group_alice_1234.tree.print(&format!("\n{:?}", ms3));

    // Alice updates and Bob commits
    let update_proposal_alice = group_alice_1234.create_update_proposal(None);
    group_bob.process_proposal(update_proposal_alice);
    let (commit4, ms4, _) = group_bob.create_commit(None);

    group_bob.process_commit(commit4.clone());
    group_alice_1234.process_commit(commit4);

    group_alice_1234.tree.print(&format!("\n{:?}", ms4));

    // Bob updates and Alice commits
    let update_proposal_bob = group_bob.create_update_proposal(None);
    group_alice_1234.process_proposal(update_proposal_bob);
    let (commit5, ms5, _) = group_alice_1234.create_commit(None);

    group_alice_1234.process_commit(commit5.clone());
    group_bob.process_commit(commit5);

    group_alice_1234.tree.print(&format!("\n{:?}", ms5));

    // Bob adds Charlie
    let add_proposal = group_bob.create_add_proposal(&charlie_key_package, None);
    group_alice_1234.process_proposal(add_proposal);

    let (commit6, ms6, welcome_bundle_bob_charlie) = group_bob.create_commit(None);

    group_alice_1234.process_commit(commit6.clone());
    group_bob.process_commit(commit6);

    let mut group_charlie = Group::new_from_welcome(
        charlie_identity,
        welcome_bundle_bob_charlie.unwrap(),
        charlie_key_package_bundle,
    );

    group_alice_1234.tree.print(&format!("\n{:?}", ms6));

    // Charlie updates
    let update_proposal_charlie = group_charlie.create_update_proposal(None);

    group_alice_1234.process_proposal(update_proposal_charlie.clone());
    group_bob.process_proposal(update_proposal_charlie);

    let (commit7, ms7, _) = group_charlie.create_commit(None);

    group_alice_1234.process_commit(commit7.clone());
    group_bob.process_commit(commit7.clone());
    group_charlie.process_commit(commit7);

    group_alice_1234.tree.print(&format!("\n{:?}", ms7));

    // Alice updates
    let update_proposal_alice = group_alice_1234.create_update_proposal(None);

    group_bob.process_proposal(update_proposal_alice.clone());
    group_charlie.process_proposal(update_proposal_alice);

    let (commit8, ms8, _) = group_alice_1234.create_commit(None);

    group_alice_1234.process_commit(commit8.clone());
    group_bob.process_commit(commit8.clone());
    group_charlie.process_commit(commit8);

    group_alice_1234.tree.print(&format!("\n{:?}", ms8));

    // Charlie removes Bob
    let remove_proposal_charlie = group_charlie.create_remove_proposal(2, None);

    group_alice_1234.process_proposal(remove_proposal_charlie.clone());
    group_bob.process_proposal(remove_proposal_charlie);

    let (commit9, ms9, _) = group_charlie.create_commit(None);

    group_alice_1234.process_commit(commit9.clone());
    group_bob.process_commit(commit9.clone());
    group_charlie.process_commit(commit9);

    group_alice_1234.tree.print(&format!("\n{:?}", ms9));
}
*/
