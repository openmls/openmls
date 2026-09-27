//! Tests for the non-standard per-message key export extension.
#![cfg(feature = "message-key-export")]

use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{crypto::OpenMlsCrypto, OpenMlsProvider};

const CS: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

fn member(name: &[u8], provider: &OpenMlsRustCrypto) -> (CredentialWithKey, SignatureKeyPair) {
    let keys = SignatureKeyPair::new(CS.signature_algorithm()).unwrap();
    keys.store(provider.storage()).unwrap();
    (
        CredentialWithKey {
            credential: BasicCredential::new(name.to_vec()).into(),
            signature_key: keys.to_public_vec().into(),
        },
        keys,
    )
}

/// A two-member (Alice, Bob) group, mirroring `audit_escrow.rs`.
fn two_member_group() -> (
    OpenMlsRustCrypto,
    MlsGroup,
    SignatureKeyPair,
    OpenMlsRustCrypto,
    MlsGroup,
) {
    let alice_p = OpenMlsRustCrypto::default();
    let bob_p = OpenMlsRustCrypto::default();

    let (alice_cred, alice_keys) = member(b"Alice", &alice_p);
    let (bob_cred, bob_keys) = member(b"Bob", &bob_p);
    let bob_kp = KeyPackage::builder()
        .build(CS, &bob_p, &bob_keys, bob_cred)
        .unwrap();

    let create_cfg = MlsGroupCreateConfig::builder()
        .ciphersuite(CS)
        .use_ratchet_tree_extension(true)
        .build();
    let mut alice = MlsGroup::new(&alice_p, &alice_keys, &create_cfg, alice_cred).unwrap();
    let (_, welcome, _) = alice
        .add_members(
            &alice_p,
            &alice_keys,
            core::slice::from_ref(bob_kp.key_package()),
        )
        .unwrap();
    alice.merge_pending_commit(&alice_p).unwrap();

    let welcome = MlsMessageIn::from(welcome).into_welcome().unwrap();
    let join_cfg = MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build();
    let bob = StagedWelcome::new_from_welcome(&bob_p, &join_cfg, welcome, None)
        .unwrap()
        .into_group(&bob_p)
        .unwrap();

    (alice_p, alice, alice_keys, bob_p, bob)
}

/// Pull the `PrivateMessageIn` out of wire bytes, as an escrow service would.
fn private_message_from_wire(bytes: &[u8]) -> PrivateMessageIn {
    match MlsMessageIn::tls_deserialize_exact(bytes).unwrap().extract() {
        MlsMessageBodyIn::PrivateMessage(m) => m,
        _ => panic!("expected PrivateMessage"),
    }
}

/// Rebuild the `PrivateContentAad` bytes exactly as the sender did, from the
/// public getters on `PrivateMessageIn`. Field order matches the
/// `PrivateContentAad` TLS struct: group_id, epoch, content_type,
/// authenticated_data.
fn content_aad(pm: &PrivateMessageIn) -> Vec<u8> {
    let mut aad = Vec::new();
    pm.group_id().tls_serialize(&mut aad).unwrap();
    pm.epoch().tls_serialize(&mut aad).unwrap();
    pm.content_type().tls_serialize(&mut aad).unwrap();
    VLByteSlice(pm.aad()).tls_serialize(&mut aad).unwrap();
    aad
}

#[test]
fn exported_key_opens_the_ciphertext() {
    let (alice_p, mut alice, alice_keys, _bob_p, _bob) = two_member_group();

    let (msg_out, exported) = alice
        .create_message_with_key_export(&alice_p, &alice_keys, b"hello bob")
        .unwrap();

    // The exported key describes exactly this message.
    assert_eq!(exported.group_id(), alice.group_id());
    assert_eq!(exported.epoch().as_u64(), alice.epoch().as_u64());
    assert_eq!(exported.sender_leaf_index(), alice.own_leaf_index().u32());
    assert_eq!(exported.generation(), 0);

    // Serialize + deserialize the wire message, as a third party would.
    let wire = msg_out.tls_serialize_detached().unwrap();
    let pm = private_message_from_wire(&wire);

    // The exported ciphertext matches the one on the wire.
    assert_eq!(exported.ciphertext(), pm.ciphertext());

    // Decrypt the ciphertext directly with the exported key/nonce + rebuilt AAD.
    let aad = content_aad(&pm);
    let plaintext = alice_p
        .crypto()
        .aead_decrypt(
            CS.aead_algorithm(),
            exported.key(),
            pm.ciphertext(),
            exported.nonce().as_slice(),
            &aad,
        )
        .expect("exported key must open the ciphertext");

    // The decrypted `PrivateMessageContent` begins with the application data
    // (a VLBytes), followed by auth data and padding.
    let mut cursor = plaintext.as_slice();
    let application_data = VLBytes::tls_deserialize(&mut cursor).unwrap();
    assert_eq!(application_data.as_slice(), b"hello bob");
}

#[test]
fn receiver_decrypts_unchanged() {
    let (alice_p, mut alice, alice_keys, bob_p, mut bob) = two_member_group();

    let (msg_out, _exported) = alice
        .create_message_with_key_export(&alice_p, &alice_keys, b"hello bob")
        .unwrap();

    // Bob processes the very same wire message: the wire format is untouched.
    let wire = msg_out.tls_serialize_detached().unwrap();
    let protocol_message = MlsMessageIn::tls_deserialize_exact(&wire)
        .unwrap()
        .try_into_protocol_message()
        .unwrap();
    let processed = bob.process_message(&bob_p, protocol_message).unwrap();
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(m) => {
            assert_eq!(m.into_bytes(), b"hello bob");
        }
        _ => panic!("expected application message"),
    }
}

#[test]
fn each_message_exports_a_distinct_key() {
    let (alice_p, mut alice, alice_keys, _bob_p, _bob) = two_member_group();

    let (_m1, k1) = alice
        .create_message_with_key_export(&alice_p, &alice_keys, b"first")
        .unwrap();
    let (_m2, k2) = alice
        .create_message_with_key_export(&alice_p, &alice_keys, b"second")
        .unwrap();

    // Consecutive messages in the same epoch ratchet forward.
    assert_eq!(k1.generation(), 0);
    assert_eq!(k2.generation(), 1);
    assert_ne!(k1.key(), k2.key());
    assert_ne!(k1.nonce(), k2.nonce());
}
