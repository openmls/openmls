#![allow(non_snake_case)]

use crate::{
    ciphersuite::hash_ref::KeyPackageRef,
    ciphersuite::{signable::Signable, AeadKey, AeadNonce, Mac, Secret},
    credentials::{CredentialBundle, CredentialType},
    group::GroupId,
    messages::{ConfirmationTag, EncryptedGroupSecrets, GroupInfoPayload, Welcome},
    versions::ProtocolVersion,
};

use rstest::*;
use rstest_reuse::{self, *};

use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::{
    crypto::OpenMlsCrypto, random::OpenMlsRand, types::Ciphersuite, OpenMlsCryptoProvider,
};
use tls_codec::{Deserialize, Serialize};

#[apply(ciphersuites_and_backends)]
fn test_welcome_msg(ciphersuite: Ciphersuite, backend: &impl OpenMlsCryptoProvider) {
    test_welcome_message_with_version(ciphersuite, backend, ProtocolVersion::Mls10);
}

fn test_welcome_message_with_version(
    ciphersuite: Ciphersuite,
    backend: &impl OpenMlsCryptoProvider,
    version: ProtocolVersion,
) {
    // We use this dummy group info in all test cases.
    let group_info = GroupInfoPayload::new(
        GroupId::random(backend),
        123,
        vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        vec![1, 1, 1],
        &Vec::new(),
        &Vec::new(),
        ConfirmationTag(Mac {
            mac_value: vec![1, 2, 3, 4, 5].into(),
        }),
        &KeyPackageRef::from_slice(
            &backend
                .rand()
                .random_vec(16)
                .expect("An unexpected error occurred."),
        ),
    );

    // We need a credential bundle to sign the group info.
    let credential_bundle = CredentialBundle::new(
        "XXX".into(),
        CredentialType::Basic,
        ciphersuite.signature_algorithm(),
        backend,
    )
    .expect("An unexpected error occurred.");
    let group_info = group_info
        .sign(backend, &credential_bundle)
        .expect("Error signing GroupInfo");

    // Generate key and nonce for the symmetric cipher.
    let welcome_key = AeadKey::random(ciphersuite, backend.rand());
    let welcome_nonce = AeadNonce::random(backend);

    // Generate receiver key pair.
    let receiver_key_pair = backend.crypto().derive_hpke_keypair(
        ciphersuite.hpke_config(),
        Secret::random(ciphersuite, backend, None)
            .expect("Not enough randomness.")
            .as_slice(),
    );
    let hpke_info = b"group info welcome test info";
    let hpke_aad = b"group info welcome test aad";
    let hpke_input = b"these should be the group secrets";
    let new_member = KeyPackageRef::from_slice(&[0u8; 16]);
    let secrets = vec![EncryptedGroupSecrets {
        new_member,
        encrypted_group_secrets: backend.crypto().hpke_seal(
            ciphersuite.hpke_config(),
            receiver_key_pair.public.as_slice(),
            hpke_info,
            hpke_aad,
            hpke_input,
        ),
    }];

    // Encrypt the group info.
    let encrypted_group_info = welcome_key
        .aead_seal(
            backend,
            &group_info
                .tls_serialize_detached()
                .expect("An unexpected error occurred."),
            &[],
            &welcome_nonce,
        )
        .expect("An unexpected error occurred.");

    // Now build the welcome message.
    let msg = Welcome::new(version, ciphersuite, secrets, encrypted_group_info.clone());

    // Encode, decode and re-assemble
    let msg_encoded = msg
        .tls_serialize_detached()
        .expect("An unexpected error occurred.");
    println!("encoded msg: {:?}", msg_encoded);
    let msg_decoded = Welcome::tls_deserialize(&mut msg_encoded.as_slice())
        .expect("An unexpected error occurred.");

    // Check that the welcome message is the same
    assert_eq!(msg_decoded.version, version);
    assert_eq!(msg_decoded.cipher_suite, ciphersuite);
    for secret in msg_decoded.secrets.iter() {
        assert_eq!(new_member.as_slice(), secret.new_member.as_slice());
        let ptxt = backend
            .crypto()
            .hpke_open(
                ciphersuite.hpke_config(),
                &secret.encrypted_group_secrets,
                &receiver_key_pair.private,
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
