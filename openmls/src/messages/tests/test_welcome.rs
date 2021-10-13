#![allow(non_snake_case)]

use crate::{
    ciphersuite::{signable::Signable, AeadKey, AeadNonce, CiphersuiteName, Mac, Secret},
    config::Config,
    credentials::{CredentialBundle, CredentialType},
    group::{GroupEpoch, GroupId},
    messages::{ConfirmationTag, EncryptedGroupSecrets, GroupInfoPayload, Welcome},
    tree::index::LeafIndex,
};

use rust_crypto::RustCrypto;
use tls_codec::{Deserialize, Serialize};

macro_rules! test_welcome_msg {
    ($name:ident, $ciphersuite:expr, $version:expr) => {
        #[test]
        fn $name() {
            let crypto = RustCrypto::default();
            // We use this dummy group info in all test cases.
            let group_info = GroupInfoPayload::new(
                GroupId::random(&crypto),
                GroupEpoch(123),
                vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
                vec![1, 1, 1],
                Vec::new(),
                ConfirmationTag(Mac {
                    mac_value: vec![1, 2, 3, 4, 5].into(),
                }),
                LeafIndex::from(8u32),
            );

            // We need a credential bundle to sign the group info.
            let credential_bundle = CredentialBundle::new(
                "XXX".into(),
                CredentialType::Basic,
                $ciphersuite.signature_scheme(),
                &crypto,
            )
            .unwrap();
            let group_info = group_info
                .sign(&crypto, &credential_bundle)
                .expect("Error signing GroupInfo");

            // Generate key and nonce for the symmetric cipher.
            let welcome_key = AeadKey::random($ciphersuite);
            let welcome_nonce = AeadNonce::random(&crypto);

            // Generate receiver key pair.
            let receiver_key_pair =
                $ciphersuite.derive_hpke_keypair(&Secret::random($ciphersuite, &crypto, None));
            let hpke_info = b"group info welcome test info";
            let hpke_aad = b"group info welcome test aad";
            let hpke_input = b"these should be the group secrets";
            let key_package_hash = vec![0, 0, 0, 0];
            let secrets = vec![EncryptedGroupSecrets {
                key_package_hash: key_package_hash.clone().into(),
                encrypted_group_secrets: $ciphersuite.hpke_seal(
                    receiver_key_pair.public_key(),
                    hpke_info,
                    hpke_aad,
                    hpke_input,
                ),
            }];

            // Encrypt the group info.
            let encrypted_group_info = welcome_key
                .aead_seal(
                    &crypto,
                    &group_info.tls_serialize_detached().unwrap(),
                    &[],
                    &welcome_nonce,
                )
                .unwrap();

            // Now build the welcome message.
            let msg = Welcome::new(
                $version,
                $ciphersuite,
                secrets,
                encrypted_group_info.clone(),
            );

            // Encode, decode and re-assemble
            let msg_encoded = msg.tls_serialize_detached().unwrap();
            println!("encoded msg: {:?}", msg_encoded);
            let msg_decoded = Welcome::tls_deserialize(&mut msg_encoded.as_slice()).unwrap();

            // Check that the welcome message is the same
            assert_eq!(msg_decoded.version, $version);
            assert_eq!(msg_decoded.cipher_suite, $ciphersuite.name());
            for secret in msg_decoded.secrets.iter() {
                assert_eq!(
                    key_package_hash.as_slice(),
                    secret.key_package_hash.as_slice()
                );
                let ptxt = $ciphersuite
                    .hpke_open(
                        &secret.encrypted_group_secrets,
                        receiver_key_pair.private_key(),
                        hpke_info,
                        hpke_aad,
                    )
                    .expect("Error decrypting valid ciphertext in Welcome message test.");
                assert_eq!(&hpke_input[..], &ptxt[..]);
            }
            assert_eq!(
                msg_decoded.encrypted_group_info.as_slice(),
                encrypted_group_info.as_slice()
            );
        }
    };
}

test_welcome_msg!(
    test_welcome_MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    Config::ciphersuite(CiphersuiteName::MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519).unwrap(),
    Config::supported_versions()[0]
);

test_welcome_msg!(
    test_welcome_MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519,
    Config::ciphersuite(CiphersuiteName::MLS10_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519)
        .unwrap(),
    Config::supported_versions()[0]
);

test_welcome_msg!(
    test_welcome_MLS10_128_DHKEMP256_AES128GCM_SHA256_P256,
    Config::ciphersuite(CiphersuiteName::MLS10_128_DHKEMP256_AES128GCM_SHA256_P256).unwrap(),
    Config::supported_versions()[0]
);

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
