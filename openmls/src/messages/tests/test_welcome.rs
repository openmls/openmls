use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto, key_store::OpenMlsKeyStore, types::Ciphersuite, OpenMlsProvider,
};
use rstest::*;
use rstest_reuse::{self, *};
use tls_codec::{Deserialize, Serialize};

use crate::{
    binary_tree::LeafNodeIndex,
    ciphersuite::{
        hash_ref::KeyPackageRef, hpke, signable::Signable, AeadKey, AeadNonce, Mac, Secret,
    },
    extensions::Extensions,
    group::{
        config::CryptoConfig, errors::WelcomeError, GroupContext, GroupId, MlsGroup,
        MlsGroupConfigBuilder,
    },
    messages::{
        group_info::{GroupInfoTBS, VerifiableGroupInfo},
        ConfirmationTag, EncryptedGroupSecrets, GroupSecrets, GroupSecretsError, Welcome,
    },
    prelude::HpkePrivateKey,
    schedule::{
        psk::{load_psks, store::ResumptionPskStore, PskSecret},
        KeySchedule,
    },
    treesync::node::encryption_keys::EncryptionKeyPair,
    versions::ProtocolVersion,
};

/// This test detects if the decryption of the encrypted group secrets fails due to a change in
/// the encrypted group info. As the group info is part of the decryption context of the encrypted
/// group info, it is not possible to generate a matching encrypted group context with different
/// parameters.
#[apply(ciphersuites_and_providers)]
fn test_welcome_context_mismatch(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    let _ = pretty_env_logger::try_init();

    // We need a ciphersuite that is different from the current one to create
    // the mismatch
    let mismatched_ciphersuite = match ciphersuite {
        Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
            Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519
        }
        _ => Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    };

    let group_id = GroupId::random(provider.rand());
    let mls_group_config = MlsGroupConfigBuilder::new()
        .crypto_config(CryptoConfig::with_default_version(ciphersuite))
        .build();

    let (alice_credential_with_key, _alice_kpb, alice_signer, _alice_signature_key) =
        crate::group::test_core_group::setup_client("Alice", ciphersuite, provider);
    let (_bob_credential, bob_kpb, _bob_signer, _bob_signature_key) =
        crate::group::test_core_group::setup_client("Bob", ciphersuite, provider);

    let bob_kp = bob_kpb.key_package();
    let bob_private_key = bob_kpb.private_key();

    // === Alice creates a group  and adds Bob ===
    let mut alice_group = MlsGroup::new_with_group_id(
        provider,
        &alice_signer,
        &mls_group_config,
        group_id,
        alice_credential_with_key,
    )
    .expect("An unexpected error occurred.");

    let (_queued_message, welcome, _group_info) = alice_group
        .add_members(provider, &alice_signer, &[bob_kp.clone()])
        .expect("Could not add member to group.");

    alice_group
        .merge_pending_commit(provider)
        .expect("error merging pending commit");

    let mut welcome = welcome.into_welcome().expect("Unexpected message type.");

    let original_welcome = welcome.clone();

    // === Deconstruct the Welcome message and change the ciphersuite ===

    let egs = welcome.secrets[0].clone();

    let group_secrets_bytes = hpke::decrypt_with_label(
        bob_private_key,
        "Welcome",
        welcome.encrypted_group_info(),
        egs.encrypted_group_secrets(),
        ciphersuite,
        provider.crypto(),
    )
    .expect("Could not decrypt group secrets.");
    let group_secrets = GroupSecrets::tls_deserialize(&mut group_secrets_bytes.as_slice())
        .expect("Could not deserialize group secrets.")
        .config(ciphersuite, ProtocolVersion::Mls10);
    let joiner_secret = group_secrets.joiner_secret;

    // Prepare the PskSecret
    let psk_secret = {
        let resumption_psk_store = ResumptionPskStore::new(1024);

        let psks = load_psks(provider.key_store(), &resumption_psk_store, &[]).unwrap();

        PskSecret::new(provider.crypto(), ciphersuite, psks).unwrap()
    };

    // Create key schedule
    let key_schedule =
        KeySchedule::init(ciphersuite, provider.crypto(), &joiner_secret, psk_secret)
            .expect("Could not create KeySchedule.");

    // Derive welcome key & nonce from the key schedule
    let (welcome_key, welcome_nonce) = key_schedule
        .welcome(provider.crypto())
        .expect("Using the key schedule in the wrong state")
        .derive_welcome_key_nonce(provider.crypto())
        .expect("Could not derive welcome key and nonce.");

    let group_info_bytes = welcome_key
        .aead_open(
            provider.crypto(),
            welcome.encrypted_group_info(),
            &[],
            &welcome_nonce,
        )
        .expect("Could not decrypt GroupInfo.");
    let mut verifiable_group_info =
        VerifiableGroupInfo::tls_deserialize(&mut group_info_bytes.as_slice()).unwrap();

    // Manipulate the ciphersuite in the GroupInfo
    verifiable_group_info
        .payload_mut()
        .group_context_mut()
        .set_ciphersuite(mismatched_ciphersuite);

    // === Reconstruct the Welcome message and try to process it ===

    let verifiable_group_info_bytes = verifiable_group_info.tls_serialize_detached().unwrap();

    let encrypted_verifiable_group_info = welcome_key
        .aead_seal(
            provider.crypto(),
            &verifiable_group_info_bytes,
            &[],
            &welcome_nonce,
        )
        .unwrap();

    welcome.encrypted_group_info = encrypted_verifiable_group_info.into();

    // Create backup of encryption keypair, s.t. we can process the welcome a second time after failing.
    let encryption_keypair = EncryptionKeyPair::read_from_key_store(
        provider,
        bob_kpb.key_package().leaf_node().encryption_key(),
    )
    .unwrap();

    // Bob tries to join the group
    let err = MlsGroup::new_from_welcome(
        provider,
        &mls_group_config,
        welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect_err("Created a group from an invalid Welcome.");

    assert_eq!(
        err,
        WelcomeError::GroupSecrets(GroupSecretsError::DecryptionFailed)
    );

    // === Process the original Welcome ===

    // We need to store the key package and its encryption key again because it
    // has been consumed already.
    provider
        .key_store()
        .store(
            bob_kp.hash_ref(provider.crypto()).unwrap().as_slice(),
            bob_kp,
        )
        .unwrap();
    provider
        .key_store()
        .store::<HpkePrivateKey>(bob_kp.hpke_init_key().as_slice(), bob_private_key)
        .unwrap();

    encryption_keypair
        .write_to_key_store(provider.key_store())
        .unwrap();

    let _group = MlsGroup::new_from_welcome(
        provider,
        &mls_group_config,
        original_welcome,
        Some(alice_group.export_ratchet_tree().into()),
    )
    .expect("Error creating group from a valid Welcome.");
}

#[apply(ciphersuites_and_providers)]
fn test_welcome_msg(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    test_welcome_message(ciphersuite, provider);
}

fn test_welcome_message(ciphersuite: Ciphersuite, provider: &impl OpenMlsProvider) {
    // We use this dummy group info in all test cases.
    let group_info_tbs = {
        let group_context = GroupContext::new(
            ciphersuite,
            GroupId::random(provider.rand()),
            123,
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
            vec![1, 1, 1],
            Extensions::empty(),
        );

        GroupInfoTBS::new(
            group_context,
            Extensions::empty(),
            ConfirmationTag(Mac {
                mac_value: vec![1, 2, 3, 4, 5].into(),
            }),
            LeafNodeIndex::new(1),
        )
    };

    // We need a signer
    let signer = SignatureKeyPair::new(ciphersuite.signature_algorithm()).unwrap();

    let group_info = group_info_tbs
        .sign(&signer)
        .expect("Error signing GroupInfo");

    // Generate key and nonce for the symmetric cipher.
    let welcome_key = AeadKey::random(ciphersuite, provider.rand());
    let welcome_nonce = AeadNonce::random(provider.rand());

    // Generate receiver key pair.
    let receiver_key_pair = provider.crypto().derive_hpke_keypair(
        ciphersuite.hpke_config(),
        Secret::random(ciphersuite, provider.rand(), None)
            .expect("Not enough randomness.")
            .as_slice(),
    );
    let hpke_context = b"group info welcome test info";
    let group_secrets = b"these should be the group secrets";
    let new_member = KeyPackageRef::from_slice(&[0u8; 16]);
    let secrets = vec![EncryptedGroupSecrets {
        new_member: new_member.clone(),
        encrypted_group_secrets: hpke::encrypt_with_label(
            receiver_key_pair.public.as_slice(),
            "Welcome",
            hpke_context,
            group_secrets,
            ciphersuite,
            provider.crypto(),
        )
        .unwrap(),
    }];

    // Encrypt the group info.
    let encrypted_group_info = welcome_key
        .aead_seal(
            provider.crypto(),
            &group_info
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
            &[],
            &welcome_nonce,
        )
        .expect("An unexpected error occurred.");

    // Now build the welcome message.
    let msg = Welcome::new(ciphersuite, secrets, encrypted_group_info.clone());

    // Encode, decode and re-assemble
    let msg_encoded = msg
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    println!("encoded msg: {msg_encoded:?}");
    let msg_decoded = Welcome::tls_deserialize(&mut msg_encoded.as_slice())
        .expect("An unexpected error occurred.");

    // Check that the welcome message is the same
    assert_eq!(msg_decoded.cipher_suite, ciphersuite);
    for secret in msg_decoded.secrets.iter() {
        assert_eq!(new_member.as_slice(), secret.new_member.as_slice());
        let ptxt = hpke::decrypt_with_label(
            &receiver_key_pair.private,
            "Welcome",
            hpke_context,
            &secret.encrypted_group_secrets,
            ciphersuite,
            provider.crypto(),
        )
        .expect("Error decrypting valid ciphertext in Welcome message test.");
        assert_eq!(&group_secrets[..], &ptxt[..]);
    }
    assert_eq!(
        msg_decoded.encrypted_group_info.as_slice(),
        encrypted_group_info.as_slice()
    );
}

#[test]
fn invalid_welcomes() {
    // An almost good welcome message.
    let mut bytes = &[
        2u8, 0, 2, 0, 0, 0, 90, 4, 0, 0, 0, 0, 0, 32, 183, 76, 159, 248, 180, 5, 79, 86, 242, 165,
        206, 103, 47, 8, 110, 250, 81, 48, 206, 185, 186, 104, 220, 181, 245, 106, 134, 32, 97,
        233, 141, 26, 0, 49, 13, 203, 68, 119, 97, 90, 172, 36, 170, 239, 80, 191, 63, 146, 177,
        211, 151, 152, 93, 117, 192, 136, 96, 22, 168, 213, 67, 165, 244, 165, 183, 228, 88, 62,
        232, 36, 220, 224, 93, 216, 155, 210, 167, 34, 112, 7, 73, 42, 2, 0, 0, 0, 71, 254, 148,
        190, 32, 30, 92, 51, 15, 16, 11, 46, 196, 65, 132, 142, 111, 177, 115, 21, 218, 71, 51,
        118, 228, 188, 12, 134, 23, 216, 51, 20, 138, 215, 232, 62, 216, 119, 242, 93, 164, 250,
        100, 223, 214, 94, 85, 139, 159, 205, 193, 153, 181, 243, 139, 12, 78, 253, 200, 47, 207,
        79, 86, 82, 63, 217, 126, 204, 178, 24, 199, 49,
    ] as &[u8];
    let msg = Welcome::tls_deserialize(&mut bytes);
    assert!(msg.is_err());
}
