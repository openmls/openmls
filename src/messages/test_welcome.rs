use super::{EncryptedGroupSecrets, GroupInfo, Welcome};
use crate::{
    ciphersuite::{AeadKey, AeadNonce, Ciphersuite, Secret, Signature},
    codec::*,
    config::Config,
    group::{GroupEpoch, GroupId},
    tree::index::LeafIndex,
    utils::*,
};

macro_rules! test_welcome_msg {
    ($name:ident, $suite:expr, $version:expr) => {
        #[test]
        fn $name() {
            // We use this dummy group info in all test cases.
            let group_info = GroupInfo {
                group_id: GroupId::random(),
                epoch: GroupEpoch(123),
                tree_hash: vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
                confirmed_transcript_hash: vec![1, 1, 1],
                extensions: Vec::new(),
                confirmation_tag: vec![6, 6, 6],
                signer_index: LeafIndex::from(8u32),
                signature: Signature::new_empty(),
            };

            let ciphersuite = Ciphersuite::new($suite);

            // Generate key and nonce for the symmetric cipher.
            let welcome_key = AeadKey::new_from_random(ciphersuite.aead_mode());
            let welcome_nonce =
                AeadNonce::from_slice(&randombytes(ciphersuite.aead_nonce_length()));

            // Generate receiver key pair.
            let receiver_key_pair =
                ciphersuite.derive_hpke_keypair(&Secret::from([1u8, 2u8, 3u8, 4u8].to_vec()));
            let hpke_info = b"group info welcome test info";
            let hpke_aad = b"group info welcome test aad";
            let hpke_input = b"these should be the group secrets";
            let secrets = vec![EncryptedGroupSecrets {
                key_package_hash: vec![0, 0, 0, 0],
                encrypted_group_secrets: ciphersuite.hpke_seal(
                    receiver_key_pair.get_public_key_ref(),
                    hpke_info,
                    hpke_aad,
                    hpke_input,
                ),
            }];

            // Encrypt the group info.
            let encrypted_group_info = welcome_key
                .aead_seal(&group_info.encode_detached().unwrap(), &[], &welcome_nonce)
                .unwrap();

            // Now build the welcome message.
            let msg = Welcome::new($version, $suite, secrets, encrypted_group_info.clone());

            // Encode, decode and re-assemble
            let msg_encoded = msg.encode_detached().unwrap();
            println!("encoded msg: {:?}", msg_encoded);
            let mut cursor = Cursor::new(&msg_encoded);
            let msg_decoded = Welcome::decode(&mut cursor).unwrap();

            // Check that the welcome message is the same
            assert_eq!(msg_decoded.version, $version);
            assert_eq!(msg_decoded.cipher_suite, $suite);
            for secret in msg_decoded.secrets {
                assert_eq!(secret.key_package_hash, secret.key_package_hash);
                let ptxt = ciphersuite.hpke_open(
                    &secret.encrypted_group_secrets,
                    receiver_key_pair.get_private_key_ref(),
                    hpke_info,
                    hpke_aad,
                );
                assert_eq!(&hpke_input[..], &ptxt[..]);
            }
            assert_eq!(msg_decoded.encrypted_group_info, encrypted_group_info);
        }
    };
}

test_welcome_msg!(
    test_welcome_1_1,
    Config::supported_ciphersuites()[0],
    Config::supported_versions()[0]
);

test_welcome_msg!(
    test_welcome_2_1,
    Config::supported_ciphersuites()[1],
    Config::supported_versions()[0]
);

test_welcome_msg!(
    test_welcome_3_1,
    Config::supported_ciphersuites()[2],
    Config::supported_versions()[0]
);

#[test]
fn invalid_welcomes() {
    // An almost good welcome message.
    let bytes = [
        2, 0, 2, 0, 0, 0, 90, 4, 0, 0, 0, 0, 0, 32, 183, 76, 159, 248, 180, 5, 79, 86, 242, 165,
        206, 103, 47, 8, 110, 250, 81, 48, 206, 185, 186, 104, 220, 181, 245, 106, 134, 32, 97,
        233, 141, 26, 0, 49, 13, 203, 68, 119, 97, 90, 172, 36, 170, 239, 80, 191, 63, 146, 177,
        211, 151, 152, 93, 117, 192, 136, 96, 22, 168, 213, 67, 165, 244, 165, 183, 228, 88, 62,
        232, 36, 220, 224, 93, 216, 155, 210, 167, 34, 112, 7, 73, 42, 2, 0, 0, 0, 71, 254, 148,
        190, 32, 30, 92, 51, 15, 16, 11, 46, 196, 65, 132, 142, 111, 177, 115, 21, 218, 71, 51,
        118, 228, 188, 12, 134, 23, 216, 51, 20, 138, 215, 232, 62, 216, 119, 242, 93, 164, 250,
        100, 223, 214, 94, 85, 139, 159, 205, 193, 153, 181, 243, 139, 12, 78, 253, 200, 47, 207,
        79, 86, 82, 63, 217, 126, 204, 178, 24, 199, 49,
    ];
    let mut cursor = Cursor::new(&bytes);
    let msg = Welcome::decode(&mut cursor);
    assert!(msg.is_err());
}
