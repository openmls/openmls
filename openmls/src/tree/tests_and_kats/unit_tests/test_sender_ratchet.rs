#[cfg(feature = "virtual-clients-draft")]
use crate::tree::dual_use_ratchet::DualUseRatchet;
use crate::{
    ciphersuite::Secret, test_utils::*, tree::secret_tree::SecretTreeError, tree::sender_ratchet::*,
};

// Test the maximum forward ratcheting
#[openmls_test::openmls_test]
fn test_max_forward_distance() {
    let provider = &Provider::default();

    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet1 = DecryptionRatchet::new(secret.clone());
    let mut ratchet2 = DecryptionRatchet::new(secret);

    // We expect this to still work
    let _secret = ratchet1
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.maximum_forward_distance(),
            configuration,
        )
        .expect("Expected decryption secret.");

    // We expect this to return an error
    let err = ratchet2
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.maximum_forward_distance() + 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInTheFuture);

    // Test if there's an overflow in the maximum forward distance check.
    ratchet1.ratchet_secret_mut().set_generation(u32::MAX - 5);
    ratchet1
        .secret_for_decryption(ciphersuite, provider.crypto(), u32::MAX - 1, configuration)
        .expect("Error ratcheting to very high generation");
}

// Test out-of-order generations
#[openmls_test::openmls_test]
fn test_out_of_order_generations() {
    let provider = &Provider::default();

    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet1 = DecryptionRatchet::new(secret);

    // Ratchet forward twice the size of the window
    for i in 0..configuration.out_of_order_tolerance() * 2 {
        let _secret = ratchet1
            .secret_for_decryption(ciphersuite, provider.crypto(), i, configuration)
            .expect("Expected decryption secret.");
    }

    // Check that secrets from before the window are not accessible anymore
    let err = ratchet1
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            configuration.out_of_order_tolerance() - 1,
            configuration,
        )
        .expect_err("Expected error.");

    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // All secrets within the window should have been deleted because of FS.
    for i in configuration.out_of_order_tolerance()..configuration.out_of_order_tolerance() * 2 {
        assert_eq!(
            ratchet1
                .secret_for_decryption(ciphersuite, provider.crypto(), i, configuration)
                .expect_err("Expected decryption secret."),
            SecretTreeError::SecretReuseError
        );
    }
}

// Test forward secrecy
#[openmls_test::openmls_test]
fn test_forward_secrecy() {
    let provider = &Provider::default();

    // Encryption Ratchets are forward-secret by default, since they don't store
    // any keys. Thus, we can only test FS on Decryption Ratchets.
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DecryptionRatchet::new(secret);

    // Let's ratchet once and see if the ratchet keeps any keys around.
    let _ratchet_secrets = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
        .expect("Error ratcheting forward.");

    // The generation should have increased.
    assert_eq!(ratchet.generation(), 1);

    // And we should get an error for generation 0.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 0, configuration)
        .expect_err("No error when trying to retrieve key outside of tolerance window.");
    assert_eq!(err, SecretTreeError::SecretReuseError);

    // Let's ratchet forward a few times, making the ratchet keep the secrets round for out-of-order decryption.
    let _ratchet_secrets = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 10, configuration)
        .expect("Error ratcheting forward.");

    // First, let's make sure that the window works.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), 5, configuration)
        .expect_err("No error when trying to retrieve key outside of tolerance window.");
    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    // Now let's get a few keys. The first time we're trying to get the key of a given generation, it should work. The second time, we should get a SecretReuseError.
    for generation in 10 - configuration.out_of_order_tolerance() + 1..10 {
        let keys = ratchet.secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            generation,
            configuration,
        );
        assert!(keys.is_ok());

        let err = ratchet
            .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
            .expect_err("No error when trying to retrieve deleted key.");
        assert_eq!(err, SecretTreeError::SecretReuseError);
    }
}

// Test if a sender ratchet overflow is caught
#[test]
fn sender_ratchet_generation_overflow() {
    let provider = OpenMlsRustCrypto::default();
    let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = RatchetSecret::initial_ratchet_secret(secret);
    ratchet.set_generation(u32::MAX - 1);
    let _ = ratchet
        .ratchet_forward(provider.crypto(), ciphersuite)
        .expect("error ratcheting forward");
    let err = ratchet
        .ratchet_forward(provider.crypto(), ciphersuite)
        .expect_err("no error exceeding generation u32::MAX");
    assert_eq!(err, SecretTreeError::RatchetTooLong)
}

// === DualUseRatchet ===
//
// The tests below cover the dual-use-only methods
// (`secret_for_encryption`, `delete_secret_for_generation`) and the
// encrypt-then-decrypt-own state machine that's unique to `DualUseRatchet`.

// Encrypting caches the secret in the past-secrets window, then `confirm`
// (i.e. `delete_secret_for_generation`) drops it, and a later attempt to
// decrypt that generation fails as `SecretReuseError`.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_encrypt_confirm_drops_secret() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let (generation, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");
    assert_eq!(generation, 0);
    assert_eq!(ratchet.generation(), 1);

    // Confirm the message, dropping the cached encryption secret.
    ratchet.delete_secret_for_generation(generation);

    // Decrypting at the same generation now fails since the entry was removed.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
        .expect_err("Confirmed secret should be unavailable.");
    assert_eq!(err, SecretTreeError::SecretReuseError);
}

// Without confirming, the local sender can decrypt their own message (the
// cached secret in the past-secrets window is removed when used). A second
// decryption attempt at the same generation then fails.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_encrypt_then_decrypt_own() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let (generation, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");

    // First decryption succeeds — the secret was cached when we encrypted.
    let _decrypted = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
        .expect("Expected to decrypt own message.");

    // Second decryption at the same generation fails.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), generation, configuration)
        .expect_err("Reusing the same generation should fail.");
    assert_eq!(err, SecretTreeError::SecretReuseError);
}

// `delete_secret_for_generation` is a no-op when the requested generation
// hasn't been emitted yet (>= the ratchet head) and is idempotent for past
// generations whose cached secret was already removed.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_delete_secret_edge_cases() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    // Deleting at the current head (generation == head, window_index == -1) is
    // a no-op.
    ratchet.delete_secret_for_generation(ratchet.generation());
    assert_eq!(ratchet.generation(), 0);

    // Deleting a future generation is also a no-op.
    ratchet.delete_secret_for_generation(42);
    assert_eq!(ratchet.generation(), 0);

    // Now emit a couple of secrets so we have entries in the past-secrets
    // window.
    let (gen0, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");
    let (_gen1, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");

    // Deleting an already-cached past generation drops it; a second delete at
    // the same generation is harmless.
    ratchet.delete_secret_for_generation(gen0);
    ratchet.delete_secret_for_generation(gen0);

    // Decrypting that generation now fails.
    let err = ratchet
        .secret_for_decryption(ciphersuite, provider.crypto(), gen0, configuration)
        .expect_err("Deleted secret should be unavailable.");
    assert_eq!(err, SecretTreeError::SecretReuseError);
}

// Encrypting more than `out_of_order_tolerance` messages without confirming or
// decrypting must not lock the local sender out of decrypting their oldest
// in-flight message: the past-bound check that's correct for a pure
// `DecryptionRatchet` (where anything that old has been pruned away) does not
// apply to a `DualUseRatchet`, because encryption keeps the secret.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_decrypts_past_out_of_order_tolerance() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    // Send more messages than `out_of_order_tolerance` so that the cache is
    // larger than the tolerance window.
    let send_count = configuration.out_of_order_tolerance() + 2;
    let mut first_generation = None;
    for _ in 0..send_count {
        let (generation, _) = ratchet
            .secret_for_encryption(ciphersuite, provider.crypto())
            .expect("Expected encryption secret.");
        first_generation.get_or_insert(generation);
    }
    let first_generation = first_generation.unwrap();
    assert!(ratchet.generation() - first_generation > configuration.out_of_order_tolerance());

    // The oldest cached secret is `out_of_order_tolerance + 1` generations
    // behind the head, but its secret is still cached, so decryption must
    // succeed.
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            first_generation,
            configuration,
        )
        .expect("Old encryption secret should still be retrievable for own decryption.");
}

// Confirming later messages must not advance the receive-side retention
// window or evict an older unconfirmed encryption secret. The older secret may
// still be needed to decrypt an own message from another virtual client.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_confirming_later_messages_keeps_old_unconfirmed_secret() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let (first_generation, _) = ratchet
        .secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");

    for _ in 0..configuration.out_of_order_tolerance() + 2 {
        let (generation, _) = ratchet
            .secret_for_encryption(ciphersuite, provider.crypto())
            .expect("Expected encryption secret.");
        ratchet.delete_secret_for_generation(generation);
    }

    assert!(ratchet.generation() - first_generation > configuration.out_of_order_tolerance());

    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            first_generation,
            configuration,
        )
        .expect("Old unconfirmed secret should still be retrievable for own decryption.");
}

// Successful decryption is what advances the receive-side window. Secrets
// derived only to cover skipped receive generations are pruned once they fall
// outside that window.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_decryption_moves_receive_window() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let target_generation = configuration.out_of_order_tolerance() * 2;
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            target_generation,
            configuration,
        )
        .expect("Expected decryption secret.");

    let too_old_generation = target_generation - configuration.out_of_order_tolerance();
    let err = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            too_old_generation,
            configuration,
        )
        .expect_err("Expected the receive window to reject old generations.");
    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    let retained_generation = target_generation - configuration.out_of_order_tolerance() + 1;
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            retained_generation,
            configuration,
        )
        .expect("Expected retained out-of-order secret.");
}

// Local sends must not occupy slots in the receive-side retention window. Only
// decrypting a message advances that window. In this scenario the first
// decryption leaves a full receive window, then we send and confirm enough
// messages to span the whole tolerance. A later decryption should prune only as
// far as that one received message requires, not by the locally sent
// generations.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_local_sends_do_not_advance_receive_window() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet = DualUseRatchet::new(secret);

    let first_received_generation = configuration.out_of_order_tolerance();
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            first_received_generation,
            configuration,
        )
        .expect("Expected first decryption secret.");

    for _ in 0..configuration.out_of_order_tolerance() {
        let (generation, _) = ratchet
            .secret_for_encryption(ciphersuite, provider.crypto())
            .expect("Expected encryption secret.");
        ratchet.delete_secret_for_generation(generation);
    }

    let later_received_generation = ratchet.generation();
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            later_received_generation,
            configuration,
        )
        .expect("Expected later decryption secret.");

    let pruned_by_later_decryption =
        first_received_generation.saturating_sub(configuration.out_of_order_tolerance()) + 1;
    let err = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            pruned_by_later_decryption,
            configuration,
        )
        .expect_err("One old generation should be pruned by the later decryption.");
    assert_eq!(err, SecretTreeError::TooDistantInThePast);

    let retained_across_local_sends = pruned_by_later_decryption + 1;
    let _decrypted = ratchet
        .secret_for_decryption(
            ciphersuite,
            provider.crypto(),
            retained_across_local_sends,
            configuration,
        )
        .expect("Local sends should not prune the receive window.");
}

// === Cross-feature persistence ===
//
// A `SecretTree` persisted by a build with a different setting of the
// `virtual-clients-draft` feature must still load. The own leaf's sender
// ratchet is a `DualUse` when the feature is on and an `EncryptionRatchet` when
// it is off, and the two serialize under different variant tags. On
// deserialization the ratchet is normalized to the representation matching the
// current feature setting. The fixtures below are the externally tagged JSON
// (as produced by the memory storage provider's serde_json backend) for each
// variant; the tests assert that loading either one yields the right in-memory
// variant under both feature settings.
//
// The fixtures were produced by serializing freshly built ratchets; the
// `*_round_trips_*` tests below guard that this on-wire shape stays stable.

// A `DualUse` ratchet at head generation 4 whose past-secrets window holds one
// `AwaitingConfirmation` entry (generation 0) and three `RetainedForDecryption`
// entries (generations 1, 2, 3).
const DUAL_USE_FIXTURE: &str = r#"{"DualUse":{"past_secrets":[[0,{"AwaitingConfirmation":[{"aead_mode":"Aes128Gcm","value":{"vec":[253,163,208,156,211,4,29,242,6,31,159,140,240,147,32,181]}},[66,147,247,188,34,115,67,54,156,29,45,85]]}],[1,{"RetainedForDecryption":{"Available":[{"aead_mode":"Aes128Gcm","value":{"vec":[78,248,98,88,0,200,245,93,100,15,35,11,191,186,188,111]}},[185,5,151,21,100,129,2,187,13,218,40,157]]}}],[2,{"RetainedForDecryption":{"Available":[{"aead_mode":"Aes128Gcm","value":{"vec":[76,176,77,172,42,35,216,131,186,71,84,243,34,1,146,15]}},[165,247,166,187,73,173,238,205,123,104,91,183]]}}],[3,{"RetainedForDecryption":"Consumed"}]],"ratchet_head":{"secret":{"value":{"vec":[235,88,101,41,245,163,189,178,33,120,83,33,244,232,122,6,166,50,7,198,8,42,17,82,24,46,126,10,123,200,92,117]}},"generation":4}}}"#;

// An `EncryptionRatchet` at generation 7.
const ENCRYPTION_FIXTURE: &str = r#"{"EncryptionRatchet":{"secret":{"value":{"vec":[61,205,226,216,74,2,96,155,236,233,72,2,173,193,202,67,186,68,75,62,126,162,196,233,243,232,73,177,2,216,66,143]}},"generation":7}}"#;

// A persisted `DualUse` ratchet loads as `DualUse` (keeping its head generation
// and its past secrets) when the feature is on, and is downgraded to an
// `EncryptionRatchet` at the same head generation (dropping the past secrets)
// when the feature is off.
#[test]
fn dual_use_fixture_normalizes_to_current_feature() {
    let ratchet: SenderRatchet =
        serde_json::from_str(DUAL_USE_FIXTURE).expect("fixture should deserialize");
    assert_eq!(ratchet.generation(), 4);

    #[cfg(feature = "virtual-clients-draft")]
    {
        let SenderRatchet::DualUse(dual) = &ratchet else {
            panic!("expected the own ratchet to load as DualUse with the feature enabled");
        };
        assert_eq!(dual.generation(), 4);
        assert_eq!(dual.past_secrets_len(), 4);
    }
    #[cfg(not(feature = "virtual-clients-draft"))]
    {
        let SenderRatchet::EncryptionRatchet(_) = &ratchet else {
            panic!("expected the own ratchet to load as EncryptionRatchet without the feature");
        };
    }
}

// A persisted `EncryptionRatchet` loads unchanged when the feature is off, and
// is upgraded to a `DualUse` (same generation, empty past-secrets window) when
// the feature is on.
#[test]
fn encryption_fixture_normalizes_to_current_feature() {
    let ratchet: SenderRatchet =
        serde_json::from_str(ENCRYPTION_FIXTURE).expect("fixture should deserialize");
    assert_eq!(ratchet.generation(), 7);

    #[cfg(feature = "virtual-clients-draft")]
    {
        let SenderRatchet::DualUse(dual) = &ratchet else {
            panic!("expected the own EncryptionRatchet to be upgraded to DualUse");
        };
        assert_eq!(dual.generation(), 7);
        assert_eq!(dual.past_secrets_len(), 0);
    }
    #[cfg(not(feature = "virtual-clients-draft"))]
    {
        let SenderRatchet::EncryptionRatchet(_) = &ratchet else {
            panic!("expected the own EncryptionRatchet to load unchanged");
        };
    }
}

// A freshly built `DualUse` ratchet serializes under the `DualUse` tag (the
// on-wire shape the fixtures rely on) and round-trips back to an equal value.
#[cfg(feature = "virtual-clients-draft")]
#[openmls_test::openmls_test]
fn dual_use_round_trips_and_keeps_variant_tag() {
    let provider = &Provider::default();
    let configuration = &SenderRatchetConfiguration::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut dual = DualUseRatchet::new(secret);
    dual.secret_for_encryption(ciphersuite, provider.crypto())
        .expect("Expected encryption secret.");
    dual.secret_for_decryption(ciphersuite, provider.crypto(), 3, configuration)
        .expect("Expected decryption secret.");

    let ratchet = SenderRatchet::DualUse(dual);
    let json = serde_json::to_string(&ratchet).expect("Expected serialization to succeed.");
    assert!(json.starts_with(r#"{"DualUse":"#));

    let restored: SenderRatchet =
        serde_json::from_str(&json).expect("Expected deserialization to succeed.");
    assert_eq!(ratchet, restored);
}

// An `EncryptionRatchet` serializes under the `EncryptionRatchet` tag. Without
// the feature it also round-trips back to an equal value; with the feature it is
// normalized to `DualUse` on load, which the fixture test above already covers.
#[openmls_test::openmls_test]
fn encryption_ratchet_keeps_variant_tag() {
    let provider = &Provider::default();
    let secret = Secret::random(ciphersuite, provider.rand()).expect("Not enough randomness.");
    let mut ratchet_secret = RatchetSecret::initial_ratchet_secret(secret);
    ratchet_secret.set_generation(7);

    let ratchet = SenderRatchet::EncryptionRatchet(ratchet_secret);
    let json = serde_json::to_string(&ratchet).expect("Expected serialization to succeed.");
    assert!(json.starts_with(r#"{"EncryptionRatchet":"#));

    #[cfg(not(feature = "virtual-clients-draft"))]
    {
        let restored: SenderRatchet =
            serde_json::from_str(&json).expect("Expected deserialization to succeed.");
        assert_eq!(ratchet, restored);
    }
}
