use maelstrom::ciphersuite::*;
use maelstrom::creds::*;
use maelstrom::framing::*;
use maelstrom::group::*;
use maelstrom::key_packages::*;

#[test]
fn create_commit_optional_path() {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let group_aad = b"Alice's test group";

    // Define identities
    let alice_identity = Identity::new(ciphersuite, "Alice".into());
    let bob_identity = Identity::new(ciphersuite, "Bob".into());

    // Define credentials
    let alice_credential = BasicCredential::from(&alice_identity);
    let bob_credential = BasicCredential::from(&bob_identity);

    // Generate KeyPackages
    let alice_key_package_bundle = KeyPackageBundle::new(
        &ciphersuite,
        &alice_identity.get_signature_key_pair().get_private_key(), // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Credential::Basic(alice_credential.clone()), // TODO: this consumes the credential!
        None,
    );

    let bob_key_package_bundle = KeyPackageBundle::new(
        &ciphersuite,
        &bob_identity.get_signature_key_pair().get_private_key(), // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Credential::Basic(bob_credential), // TODO: this consumes the credential!
        None,
    );
    let bob_key_package = bob_key_package_bundle.get_key_package();

    let alice_update_key_package_bundle = KeyPackageBundle::new(
        &ciphersuite,
        &alice_identity.get_signature_key_pair().get_private_key(), // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Credential::Basic(alice_credential),
        None,
    );
    let alice_update_key_package = alice_update_key_package_bundle.get_key_package();

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let group_alice_1234 = MlsGroup::new(&group_id, ciphersuite, alice_key_package_bundle);

    // Alice adds Bob
    let bob_add_proposal = group_alice_1234.create_add_proposal(
        group_aad,
        &alice_identity.get_signature_key_pair().get_private_key(),
        bob_key_package.clone(),
    );

    // Alice updates
    let alice_update_proposal = group_alice_1234.create_update_proposal(
        group_aad,
        &alice_identity.get_signature_key_pair().get_private_key(),
        alice_update_key_package.clone(),
    );

    // Only AddProposals
    let (commit_mls_plaintext, _welcome_option) = match group_alice_1234.create_commit(
        group_aad,
        &alice_identity.get_signature_key_pair().get_private_key(),
        vec![bob_add_proposal.clone()],
        false,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };
    let (commit, _confirmation_tag) = match commit_mls_plaintext.content {
        MLSPlaintextContentType::Commit((commit, confirmation)) => (commit, confirmation),
        _ => panic!(),
    };
    assert!(commit.path.is_none());

    // Only AddProposals with forced self update
    let (commit_mls_plaintext, _welcome_option) = match group_alice_1234.create_commit(
        group_aad,
        &alice_identity.get_signature_key_pair().get_private_key(),
        vec![bob_add_proposal],
        true,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    let (commit, _confirmation_tag) = match commit_mls_plaintext.content {
        MLSPlaintextContentType::Commit((commit, confirmation)) => (commit, confirmation),
        _ => panic!(),
    };
    assert!(commit.path.is_some());

    // Own UpdateProposal
    let (commit_mls_plaintext, _welcome_option) = match group_alice_1234.create_commit(
        group_aad,
        &alice_identity.get_signature_key_pair().get_private_key(),
        vec![alice_update_proposal],
        true,
    ) {
        Ok(c) => c,
        Err(e) => panic!("Error creating commit: {:?}", e),
    };

    let (commit, _confirmation_tag) = match commit_mls_plaintext.content {
        MLSPlaintextContentType::Commit((commit, confirmation)) => (commit, confirmation),
        _ => panic!(),
    };
    assert!(commit.path.is_some());
}
#[test]
fn basic_group_setup() {
    let ciphersuite =
        Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);
    let group_aad = b"Alice's test group";

    // Define identities
    let alice_identity = Identity::new(ciphersuite, "Alice".into());
    let bob_identity = Identity::new(ciphersuite, "Bob".into());

    // Define credentials
    let alice_credential = BasicCredential::from(&alice_identity);
    let bob_credential = BasicCredential::from(&bob_identity);

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(
        &ciphersuite,
        &bob_identity.get_signature_key_pair().get_private_key(), // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Credential::Basic(bob_credential), // TODO: this consumes the credential!
        None,
    );
    let bob_key_package = bob_key_package_bundle.get_key_package();

    let alice_key_package_bundle = KeyPackageBundle::new(
        &ciphersuite,
        &alice_identity.get_signature_key_pair().get_private_key(), // TODO: bad API, we shouldn't have to get the private key out here (this function shouldn't exist!)
        Credential::Basic(alice_credential),
        None,
    );

    // Alice creates a group
    let group_id = [1, 2, 3, 4];
    let group_alice_1234 = MlsGroup::new(&group_id, ciphersuite, alice_key_package_bundle);

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

/*
#[test]
fn group_operations() {
    let ciphersuite = Ciphersuite::new(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519);

    // Define identities
    let alice_identity = Identity::new(ciphersuite, "Alice".into());
    let bob_identity = Identity::new(ciphersuite, "Bob".into());
    let charlie_identity = Identity::new(ciphersuite, "Charlie".into());

    let _alice_credential = BasicCredential::from(&alice_identity);
    let _bob_credential = BasicCredential::from(&bob_identity);
    let _charlie_credential = BasicCredential::from(&bob_identity);

    // Generate KeyPackages
    let bob_key_package_bundle = KeyPackageBundle::new(ciphersuite, &bob_identity, None);
    let bob_key_package = bob_key_package_bundle.get_key_package();

    let charlie_key_package_bundle = KeyPackageBundle::new(ciphersuite, &charlie_identity, None);
    let charlie_key_package = charlie_key_package_bundle.get_key_package();

    // Create a group with Alice
    let config = GroupConfig::new(ciphersuite);

    let mut group_alice = Group::new(alice_identity, GroupId::random(), config);

    // Alice sends a message to herself
    let message_alice = [1, 2, 3];
    let mls_plaintext = group_alice.create_application_message(&message_alice, Some(&[4, 5, 6]));
    let encrypted_message = group_alice.encrypt(&mls_plaintext);
    let decrypted_mls_plaintext = group_alice.decrypt(&encrypted_message);
    assert_eq!(mls_plaintext, decrypted_mls_plaintext);

    // Alice adds Bob
    let _bob_add_proposal = group_alice.create_add_proposal(&bob_key_package, None);

    let (commit1, ms1, welcome_bundle_alice_bob) = group_alice.create_commit(None);

    group_alice.process_commit(commit1);

    let mut group_bob = Group::new_from_welcome(
        bob_identity,
        welcome_bundle_alice_bob.unwrap(),
        bob_key_package_bundle,
    );

    assert_eq!(group_alice.tree.nodes, group_bob.tree.nodes);
    group_alice.tree.print(&format!("\n{:?}", ms1));

    // Alice sends a message to Bob
    let message_alice = [1, 2, 3];
    let mls_plaintext_alice = group_alice.create_application_message(&message_alice, None);
    let encrypted_message = group_alice.encrypt(&mls_plaintext_alice);
    let mls_plaintext_bob = group_bob.decrypt(&encrypted_message);
    assert_eq!(mls_plaintext_alice, mls_plaintext_bob);

    // Bob updates and commits
    let update_proposal_bob = group_bob.create_update_proposal(None);
    let (commit2, ms2, _) = group_bob.create_commit(None);

    group_alice.process_proposal(update_proposal_bob);
    group_alice.process_commit(commit2.clone());
    group_bob.process_commit(commit2);

    group_alice.tree.print(&format!("\n{:?}", ms2));

    // Alice updates and commits
    let update_proposal_alice = group_alice.create_update_proposal(None);
    let (commit3, ms3, _) = group_alice.create_commit(None);

    group_bob.process_proposal(update_proposal_alice);
    group_alice.process_commit(commit3.clone());
    group_bob.process_commit(commit3);

    group_alice.tree.print(&format!("\n{:?}", ms3));

    // Alice updates and Bob commits
    let update_proposal_alice = group_alice.create_update_proposal(None);
    group_bob.process_proposal(update_proposal_alice);
    let (commit4, ms4, _) = group_bob.create_commit(None);

    group_bob.process_commit(commit4.clone());
    group_alice.process_commit(commit4);

    group_alice.tree.print(&format!("\n{:?}", ms4));

    // Bob updates and Alice commits
    let update_proposal_bob = group_bob.create_update_proposal(None);
    group_alice.process_proposal(update_proposal_bob);
    let (commit5, ms5, _) = group_alice.create_commit(None);

    group_alice.process_commit(commit5.clone());
    group_bob.process_commit(commit5);

    group_alice.tree.print(&format!("\n{:?}", ms5));

    // Bob adds Charlie
    let add_proposal = group_bob.create_add_proposal(&charlie_key_package, None);
    group_alice.process_proposal(add_proposal);

    let (commit6, ms6, welcome_bundle_bob_charlie) = group_bob.create_commit(None);

    group_alice.process_commit(commit6.clone());
    group_bob.process_commit(commit6);

    let mut group_charlie = Group::new_from_welcome(
        charlie_identity,
        welcome_bundle_bob_charlie.unwrap(),
        charlie_key_package_bundle,
    );

    group_alice.tree.print(&format!("\n{:?}", ms6));

    // Charlie updates
    let update_proposal_charlie = group_charlie.create_update_proposal(None);

    group_alice.process_proposal(update_proposal_charlie.clone());
    group_bob.process_proposal(update_proposal_charlie);

    let (commit7, ms7, _) = group_charlie.create_commit(None);

    group_alice.process_commit(commit7.clone());
    group_bob.process_commit(commit7.clone());
    group_charlie.process_commit(commit7);

    group_alice.tree.print(&format!("\n{:?}", ms7));

    // Alice updates
    let update_proposal_alice = group_alice.create_update_proposal(None);

    group_bob.process_proposal(update_proposal_alice.clone());
    group_charlie.process_proposal(update_proposal_alice);

    let (commit8, ms8, _) = group_alice.create_commit(None);

    group_alice.process_commit(commit8.clone());
    group_bob.process_commit(commit8.clone());
    group_charlie.process_commit(commit8);

    group_alice.tree.print(&format!("\n{:?}", ms8));

    // Charlie removes Bob
    let remove_proposal_charlie = group_charlie.create_remove_proposal(2, None);

    group_alice.process_proposal(remove_proposal_charlie.clone());
    group_bob.process_proposal(remove_proposal_charlie);

    let (commit9, ms9, _) = group_charlie.create_commit(None);

    group_alice.process_commit(commit9.clone());
    group_bob.process_commit(commit9.clone());
    group_charlie.process_commit(commit9);

    group_alice.tree.print(&format!("\n{:?}", ms9));
}
*/
