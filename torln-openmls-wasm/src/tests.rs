#[cfg(test)]
mod tests {
    use super::super::*;

    fn js_error_to_string(e: JsError) -> String {
        let v: JsValue = e.into();
        v.as_string().unwrap()
    }

    fn create_group_alice_and_bob() -> (Provider, Identity, Group, Provider, Identity, Group) {
        let mut alice_provider = Provider::create(None).unwrap();
        let bob_provider = Provider::create(None).unwrap();

        let alice = Identity::create(&alice_provider, "alice", None)
            .map_err(js_error_to_string)
            .unwrap();
        let bob = Identity::create(&bob_provider, "bob", None)
            .map_err(js_error_to_string)
            .unwrap();

        let mut chess_club_alice = Group::create_new(&alice_provider, &alice, "chess club");

        let bob_key_pkg = bob.get_key_package(&bob_provider);

        let add_msgs = chess_club_alice
            .native_propose_and_commit_add(&alice_provider, &alice, &bob_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club_alice
            .merge_pending_commit(&mut alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        let ratchet_tree = chess_club_alice.export_ratchet_tree();

        let chess_club_bob = Group::native_join(&bob_provider, &add_msgs.welcome, ratchet_tree);

        (
            alice_provider,
            alice,
            chess_club_alice,
            bob_provider,
            bob,
            chess_club_bob,
        )
    }

    #[test]
    fn basic() {
        let (alice_provider, _, chess_club_alice, bob_provider, _, chess_club_bob) =
            create_group_alice_and_bob();

        let bob_exported_key = chess_club_bob
            .export_secret(&bob_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();
        let alice_exported_key = chess_club_alice
            .export_secret(&alice_provider, "chess_key", &[0x30], 32)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(bob_exported_key, alice_exported_key);
    }

    #[test]
    fn create_message() {
        let (alice_provider, alice, mut chess_club_alice, mut bob_provider, _, mut chess_club_bob) =
            create_group_alice_and_bob();

        let alice_msg = "hello, bob!".as_bytes();
        let msg_out = chess_club_alice
            .create_message(&alice_provider, &alice, alice_msg)
            .map_err(js_error_to_string)
            .unwrap();

        let bob_msg = chess_club_bob
            .process_message(&mut bob_provider, &msg_out)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(alice_msg, bob_msg);
    }

    #[test]
    fn provider_with_seed() {
        let seed = [42u8; 32];

        let provider1 = OpenMlsRustCrypto::with_seed(&seed);
        let provider2 = OpenMlsRustCrypto::with_seed(&seed);

        use openmls_traits::random::OpenMlsRand;
        let buf1: [u8; 32] = provider1.rand().random_array().unwrap();
        let buf2: [u8; 32] = provider2.rand().random_array().unwrap();

        assert_eq!(buf1, buf2);
    }

    #[test]
    fn provider_with_different_seeds() {
        let seed1 = [42u8; 32];
        let seed2 = [43u8; 32];

        let provider1 = OpenMlsRustCrypto::with_seed(&seed1);
        let provider2 = OpenMlsRustCrypto::with_seed(&seed2);

        use openmls_traits::random::OpenMlsRand;
        let buf1: [u8; 32] = provider1.rand().random_array().unwrap();
        let buf2: [u8; 32] = provider2.rand().random_array().unwrap();

        assert_ne!(buf1, buf2);
    }

    #[test]
    fn identity_recovery_with_existing_keypair() {
        // Create an initial identity with a new keypair
        let provider1 = Provider::create(None).unwrap();
        let alice1 = Identity::create(&provider1, "alice", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Export the keypair
        let keypair_bytes = alice1
            .export_keypair_bytes()
            .map_err(js_error_to_string)
            .unwrap();

        // Simulate recovery: create a new provider and restore identity with the exported keypair
        let provider2 = Provider::create(None).unwrap();
        let alice2 = Identity::create(&provider2, "alice", Some(keypair_bytes))
            .map_err(js_error_to_string)
            .unwrap();

        // Verify that both identities have the same public key
        let key_pkg1 = alice1.get_key_package(&provider1);
        let key_pkg2 = alice2.get_key_package(&provider2);

        let pub_key1 = key_pkg1.0.leaf_node().signature_key().as_slice();
        let pub_key2 = key_pkg2.0.leaf_node().signature_key().as_slice();

        assert_eq!(
            pub_key1, pub_key2,
            "Public keys should match after recovery"
        );
    }

    #[test]
    fn identity_recovery_and_group_operations() {
        // Create Alice with original identity
        let mut alice_provider1 = Provider::create(None).unwrap();
        let alice1 = Identity::create(&alice_provider1, "alice", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Export Alice's keypair
        let alice_keypair_bytes = alice1
            .export_keypair_bytes()
            .map_err(js_error_to_string)
            .unwrap();

        // Alice creates a group
        let mut chess_club = Group::create_new(&alice_provider1, &alice1, "chess club");

        // Create Bob
        let mut bob_provider = Provider::create(None).unwrap();
        let bob = Identity::create(&bob_provider, "bob", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Alice adds Bob to the group
        let bob_key_pkg = bob.get_key_package(&bob_provider);
        let add_msgs = chess_club
            .native_propose_and_commit_add(&alice_provider1, &alice1, &bob_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club
            .merge_pending_commit(&mut alice_provider1)
            .map_err(js_error_to_string)
            .unwrap();

        // Bob joins the group
        let ratchet_tree = chess_club.export_ratchet_tree();
        let mut chess_club_bob = Group::native_join(&bob_provider, &add_msgs.welcome, ratchet_tree);

        // Simulate Alice recovering her identity from keypair
        let alice_provider2 = Provider::create(None).unwrap();
        let alice2 = Identity::create(&alice_provider2, "alice", Some(alice_keypair_bytes))
            .map_err(js_error_to_string)
            .unwrap();

        // Verify recovered identity has the same public key
        let key_pkg1 = alice1.get_key_package(&alice_provider1);
        let pub_key1 = key_pkg1.0.leaf_node().signature_key().as_slice();

        let key_pkg2 = alice2.get_key_package(&alice_provider2);
        let pub_key2 = key_pkg2.0.leaf_node().signature_key().as_slice();

        assert_eq!(
            pub_key1, pub_key2,
            "Recovered identity should have same public key"
        );

        // Alice sends a message using original identity
        let alice_msg = "hello from alice!".as_bytes();
        let msg_out = chess_club
            .create_message(&alice_provider1, &alice1, alice_msg)
            .map_err(js_error_to_string)
            .unwrap();

        // Bob should be able to process the message
        let received_msg = chess_club_bob
            .process_message(&mut bob_provider, &msg_out)
            .map_err(js_error_to_string)
            .unwrap();

        assert_eq!(
            alice_msg, received_msg,
            "Bob should receive Alice's message correctly"
        );
    }

    #[test]
    fn test_storage_backup_and_restore() {
        // Create Alice with a provider
        let mut alice_provider = Provider::create(None).unwrap();
        let alice = Identity::create(&alice_provider, "alice", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Create a group
        let mut chess_club = Group::create_new(&alice_provider, &alice, "chess club");
        let group_id = chess_club.group_id();

        // Create Bob
        let bob_provider = Provider::create(None).unwrap();
        let bob = Identity::create(&bob_provider, "bob", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Alice adds Bob
        let bob_key_pkg = bob.get_key_package(&bob_provider);
        let _add_msgs = chess_club
            .native_propose_and_commit_add(&alice_provider, &alice, &bob_key_pkg)
            .map_err(js_error_to_string)
            .unwrap();

        chess_club
            .merge_pending_commit(&mut alice_provider)
            .map_err(js_error_to_string)
            .unwrap();

        // Export Alice's provider storage
        let storage_backup = alice_provider
            .export_storage()
            .map_err(js_error_to_string)
            .unwrap();

        // Also backup Alice's keypair for identity recovery
        let keypair_backup = alice
            .export_keypair_bytes()
            .map_err(js_error_to_string)
            .unwrap();

        // Simulate complete recovery: new provider + restore storage + restore identity
        let restored_provider = Provider::create_from_storage(None, &storage_backup)
            .map_err(js_error_to_string)
            .unwrap();

        let restored_alice = Identity::create(&restored_provider, "alice", Some(keypair_backup))
            .map_err(js_error_to_string)
            .unwrap();

        // Load the group from restored storage
        let mut restored_group = Group::load_from_storage(&restored_provider, &group_id)
            .map_err(js_error_to_string)
            .unwrap();

        // Verify the group was restored correctly
        assert_eq!(restored_group.group_id(), group_id);

        // Verify Alice can still send messages in the restored group
        let test_msg = "hello after restore!".as_bytes();
        let msg_result =
            restored_group.create_message(&restored_provider, &restored_alice, test_msg);

        assert!(
            msg_result.is_ok(),
            "Restored Alice should be able to send messages"
        );
    }

    #[test]
    fn test_storage_import_merge() {
        // Create two separate providers with different data
        let provider1 = Provider::create(None).unwrap();
        let alice = Identity::create(&provider1, "alice", None)
            .map_err(js_error_to_string)
            .unwrap();

        let provider2 = Provider::create(None).unwrap();
        let bob = Identity::create(&provider2, "bob", None)
            .map_err(js_error_to_string)
            .unwrap();

        // Export both storages
        let storage1 = provider1.export_storage().unwrap();
        let storage2 = provider2.export_storage().unwrap();

        // Create a new provider and import both
        let merged_provider = Provider::create(None).unwrap();
        merged_provider.import_storage(&storage1).unwrap();
        merged_provider.import_storage(&storage2).unwrap();

        // Both Alice and Bob should be able to create key packages with the merged storage
        let alice_restored = Identity::create(
            &merged_provider,
            "alice",
            Some(alice.export_keypair_bytes().unwrap()),
        )
        .unwrap();

        let bob_restored = Identity::create(
            &merged_provider,
            "bob",
            Some(bob.export_keypair_bytes().unwrap()),
        )
        .unwrap();

        // Both should be able to create key packages
        let alice_pkg = alice_restored.get_key_package(&merged_provider);
        let bob_pkg = bob_restored.get_key_package(&merged_provider);

        assert_eq!(
            alice_pkg.0.leaf_node().signature_key().as_slice(),
            alice.get_public_key_bytes()
        );
        assert_eq!(
            bob_pkg.0.leaf_node().signature_key().as_slice(),
            bob.get_public_key_bytes()
        );
    }
}
